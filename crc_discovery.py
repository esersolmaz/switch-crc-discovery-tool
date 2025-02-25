#!/usr/bin/env python3
import sys
import ipaddress
import time
from collections import defaultdict
import traceback

# PySNMP'nin düzgün yüklenmesini ve importunu sağlamak için en başta deneyelim
try:
    from pysnmp.hlapi import getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
except ImportError as e:
    print(f"HATA: PySNMP kütüphanesi import edilemedi: {e}")
    print("Kütüphane yüklü olmasına rağmen bu hatayı alıyorsanız, aşağıdaki adımları deneyin:")
    print("1. pip list komutu ile pysnmp'nin yüklü olduğunu doğrulayın")
    print("2. pip uninstall pysnmp yaparak kütüphaneyi kaldırın")
    print("3. pip install pyasn1==0.4.8 ve pip install pysnmp==4.4.12 komutlarıyla uyumlu sürümleri yükleyin")
    print("4. Python'u yeniden başlatıp scripti tekrar çalıştırın")
    sys.exit(1)

# Ziyaret edilen IP'leri tutacak set
visited_ips = set()

# CRC hataları olan switch'leri ve portları tutacak dictionary
crc_errors = defaultdict(list)

def get_snmp_data(ip, oid, community='public'):
    """
    SNMP GET isteği gönderir ve sonuçları döndürür
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)))
        )
        
        if error_indication:
            print(f"SNMP Hatası: {error_indication}")
            return None
        elif error_status:
            print(f"SNMP Hatası: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}")
            return None
        else:
            return var_binds
    except Exception as e:
        print(f"SNMP GET işlemi sırasında hata: {e}")
        return None

def walk_snmp_table(ip, oid, community='public'):
    """
    SNMP WALK ile bir tabloyu alır ve sonuçları döndürür
    """
    results = []
    
    try:
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if error_indication:
                print(f"SNMP Hatası: {error_indication}")
                break
            elif error_status:
                print(f"SNMP Hatası: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}")
                break
            else:
                for var_bind in var_binds:
                    results.append(var_bind)
    except Exception as e:
        print(f"SNMP WALK işlemi sırasında hata: {e}")
        traceback.print_exc()
    
    return results

def check_crc_errors(ip, community='public'):
    """
    Switch'teki CRC hatalarını kontrol eder
    """
    print(f"\n[+] '{ip}' adresinde CRC hataları kontrol ediliyor...")
    
    # IF-MIB::ifDescr tablosunu al (port adları)
    port_descriptions = walk_snmp_table(ip, '1.3.6.1.2.1.2.2.1.2', community)
    
    # IF-MIB::ifInErrors tablosunu al
    in_errors = walk_snmp_table(ip, '1.3.6.1.2.1.2.2.1.14', community)
    
    # IF-MIB::ifOutErrors tablosunu al
    out_errors = walk_snmp_table(ip, '1.3.6.1.2.1.2.2.1.20', community)
    
    if not port_descriptions or not in_errors or not out_errors:
        print(f"[-] '{ip}' adresinden SNMP bilgisi alınamadı!")
        return
    
    # Sistemin adını al
    system_name_result = get_snmp_data(ip, '1.3.6.1.2.1.1.5.0', community)
    if system_name_result:
        system_name = system_name_result[0][1].prettyPrint()
    else:
        system_name = ip
    
    # Hata bulunan portları işle
    for i in range(len(port_descriptions)):
        port_name = port_descriptions[i][1].prettyPrint()
        
        # Port index numarasını al (OID'nin son bölümü)
        port_index = str(port_descriptions[i][0]).split('.')[-1]
        
        # Eşleşen hata sayılarını bul
        in_error_count = 0
        out_error_count = 0
        
        for error_entry in in_errors:
            if str(error_entry[0]).split('.')[-1] == port_index:
                in_error_count = int(error_entry[1])
                break
                
        for error_entry in out_errors:
            if str(error_entry[0]).split('.')[-1] == port_index:
                out_error_count = int(error_entry[1])
                break
        
        # CRC hataları varsa kaydet
        if in_error_count > 0 or out_error_count > 0:
            print(f"  - Port: {port_name}, Giriş Hataları: {in_error_count}, Çıkış Hataları: {out_error_count}")
            crc_errors[system_name].append({
                'port': port_name, 
                'in_errors': in_error_count, 
                'out_errors': out_error_count
            })

def get_lldp_neighbors(ip, community='public'):
    """
    LLDP komşularını alır ve IP adreslerini döndürür
    """
    neighbor_ips = []
    print(f"\n[+] '{ip}' adresinde LLDP komşuları alınıyor...")
    
    # LLDP-MIB::lldpRemManAddrEntry tablosunu al
    # Bu, uzak cihazın yönetim IP adreslerini içerir
    lldp_addresses = walk_snmp_table(ip, '1.0.8802.1.1.2.1.4.2', community)
    
    if not lldp_addresses:
        print(f"[-] '{ip}' adresinde LLDP komşuluk bilgisi bulunamadı!")
        return neighbor_ips
    
    # IP adreslerini ayıkla
    for entry in lldp_addresses:
        # LLDP OID'sinden IP adresini çıkarmaya çalış
        try:
            # IP adreslerini içeren OID'yi bul (genellikle adres tip 1'dir - IPv4)
            oid_str = str(entry[0])
            
            # IPv4 adreslerini içeren OID'leri filtrele
            if '.1.4.' in oid_str:  # IPv4 adresi işaretliyicidir
                # OID'nin son kısmından IP adresini çıkar
                oid_parts = oid_str.split('.')
                
                # IP adresinin baytlarını bul (son 4 bayt)
                if len(oid_parts) >= 4:
                    ip_octets = [int(x) for x in oid_parts[-4:]]
                    neighbor_ip = '.'.join(str(x) for x in ip_octets)
                    
                    # Geçerli bir IPv4 adresi mi kontrol et
                    try:
                        ipaddress.IPv4Address(neighbor_ip)
                        if neighbor_ip not in visited_ips and neighbor_ip != ip:
                            print(f"  - Bulunan komşu: {neighbor_ip}")
                            neighbor_ips.append(neighbor_ip)
                    except ValueError:
                        # Geçersiz IP adresi, atla
                        pass
        except Exception as e:
            print(f"  - LLDP verisi işlenirken hata: {e}")
    
    return neighbor_ips

def explore_network(start_ip, community='public'):
    """
    Ağı dolaşarak tüm switch'leri kontrol eder
    """
    # Keşfedilecek IP'leri tutacak kuyruk
    queue = [start_ip]
    
    while queue:
        current_ip = queue.pop(0)
        
        # Bu IP'yi daha önce ziyaret ettiysek, atla
        if current_ip in visited_ips:
            continue
        
        # IP'yi ziyaret edildi olarak işaretle
        visited_ips.add(current_ip)
        print(f"\n==== Switch: {current_ip} işleniyor ====")
        
        # CRC hatalarını kontrol et
        check_crc_errors(current_ip, community)
        
        # LLDP komşularını al
        neighbors = get_lldp_neighbors(current_ip, community)
        
        # Yeni komşuları kuyruğa ekle
        for neighbor_ip in neighbors:
            if neighbor_ip not in visited_ips:
                queue.append(neighbor_ip)
        
        # Konsola ilerlemeyi yazdır
        print(f"\n[*] Toplam ziyaret edilen cihaz sayısı: {len(visited_ips)}")
        print(f"[*] Kuyruktaki cihaz sayısı: {len(queue)}")
        print(f"[*] CRC hatası bulunan cihaz sayısı: {len(crc_errors)}")
        
        # Çok hızlı istekler göndermemek için kısa bir bekleme
        time.sleep(1)

def print_results():
    """
    Sonuçları ekrana yazdırır
    """
    print("\n\n=========== SONUÇLAR ===========")
    print(f"Toplam ziyaret edilen cihaz sayısı: {len(visited_ips)}")
    print(f"CRC hatası bulunan cihaz sayısı: {len(crc_errors)}")
    
    if crc_errors:
        print("\nCRC Hataları Bulunan Cihazlar:")
        for switch, port_list in crc_errors.items():
            print(f"\n- {switch}:")
            for port_info in port_list:
                print(f"  * Port: {port_info['port']}, Giriş Hataları: {port_info['in_errors']}, Çıkış Hataları: {port_info['out_errors']}")
    else:
        print("\nAğda CRC hatası bulunan cihaz tespit edilmedi.")
    
    print("\nZiyaret edilen tüm cihazlar:")
    for ip in visited_ips:
        print(f"- {ip}")

def save_results_to_file(filename="crc_error_report.txt"):
    """
    Sonuçları bir dosyaya kaydeder
    """
    with open(filename, 'w') as f:
        f.write("=========== CRC HATA RAPORU ===========\n")
        f.write(f"Rapor Tarihi: {time.strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"Toplam ziyaret edilen cihaz sayısı: {len(visited_ips)}\n")
        f.write(f"CRC hatası bulunan cihaz sayısı: {len(crc_errors)}\n\n")
        
        if crc_errors:
            f.write("CRC Hataları Bulunan Cihazlar:\n")
            for switch, port_list in crc_errors.items():
                f.write(f"\n- {switch}:\n")
                for port_info in port_list:
                    f.write(f"  * Port: {port_info['port']}, Giriş Hataları: {port_info['in_errors']}, Çıkış Hataları: {port_info['out_errors']}\n")
        else:
            f.write("\nAğda CRC hatası bulunan cihaz tespit edilmedi.\n")
        
        f.write("\nZiyaret edilen tüm cihazlar:\n")
        for ip in visited_ips:
            f.write(f"- {ip}\n")
    
    print(f"\n[+] Sonuçlar '{filename}' dosyasına kaydedildi.")

def main():
    print("=== Switch CRC Hata Denetleyici ===")
    print("Bu program, bir başlangıç switch'inden başlayarak ağı otomatik olarak dolaşır ve")
    print("tüm switch'lerde CRC hatalarını tespit eder.\n")
    
    # Başlangıç IP adresi
    while True:
        start_ip = input("Başlangıç switch IP adresi: ").strip()
        try:
            ipaddress.IPv4Address(start_ip)
            break
        except ValueError:
            print("Geçersiz IP adresi! Lütfen geçerli bir IPv4 adresi girin.")
    
    # SNMP community string'i
    community = input("SNMP community string: ").strip()
    if not community:
        community = "public"
        print("Community string girilmedi, varsayılan 'public' kullanılacak.")
    
    print(f"\n[*] '{start_ip}' adresinden başlayarak ağ keşfine başlanıyor...")
    print(f"[*] SNMP community: '{community}'")
    
    try:
        # Ağı dolaş ve hataları kontrol et
        explore_network(start_ip, community)
        
        # Sonuçları ekrana yazdır
        print_results()
        
        # Sonuçları dosyaya kaydet
        save_results_to_file()
        
    except KeyboardInterrupt:
        print("\n\n[!] Program kullanıcı tarafından durduruldu.")
        print_results()
        save_results_to_file()
    except Exception as e:
        print(f"\n[!] Bir hata oluştu: {e}")
        traceback.print_exc()
        
    print("\nProgram tamamlandı.")

if __name__ == "__main__":
    main()
