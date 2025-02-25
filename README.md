# Switch CRC Discovery Tool

Bu araç, ağınızdaki switch cihazlarını otomatik olarak tarayarak CRC (Cyclic Redundancy Check) hatalarını tespit eder. SNMP protokolünü kullanarak cihazlara bağlanır ve LLDP komşuluklarını takip ederek tüm ağı otomatik olarak dolaşır.

## Özellikler

- Tek bir switch'ten başlayarak tüm ağı otomatik keşfeder
- LLDP komşuluklarını kullanarak ağ topolojisini çıkarır
- CRC hatası bulunan port ve cihazları tespit eder
- Sonuçları hem ekrana yazdırır hem de dosyaya kaydeder
- Bir cihazı birden fazla kez taramayı önler

## Gereksinimler

Scriptin çalışması için aşağıdaki Python kütüphanelerine ihtiyaç vardır:

- Python 3.6 veya üzeri
- pysnmp 4.4.12
- pyasn1 0.4.8

## Kurulum

1. Bu repository'i bilgisayarınıza indirin:
```
git clone https://github.com/esersolmaz/switch-crc-discovery-tool.git
cd switch-crc-discovery-tool
```

2. Gerekli bağımlılıkları yükleyin:
```
pip install pyasn1==0.4.8
pip install pysnmp==4.4.12
```

## Kullanım

1. Scripti çalıştırın:
```
python crc_error_crawler.py
```

2. Başlangıç switch'inin IP adresini girin.

3. SNMP community string'i girin (varsayılan: "public").

4. Script otomatik olarak ağı dolaşacak ve CRC hataları olan portları tespit edecektir.

5. Sonuçlar "crc_error_report.txt" dosyasına kaydedilecektir.

## Çıktı Örneği

Script çalıştırıldığında aşağıdakine benzer bir çıktı oluşturur:

```
=========== CRC HATA RAPORU ===========
Rapor Tarihi: 25/02/2025 15:30:22
Toplam ziyaret edilen cihaz sayısı: 15
CRC hatası bulunan cihaz sayısı: 3

CRC Hataları Bulunan Cihazlar:

- Switch-A:
  * Port: GigabitEthernet1/0/5, Giriş Hataları: 125, Çıkış Hataları: 0
  * Port: GigabitEthernet1/0/12, Giriş Hataları: 47, Çıkış Hataları: 0

- Switch-B:
  * Port: GigabitEthernet2/0/3, Giriş Hataları: 78, Çıkış Hataları: 0

- Switch-C:
  * Port: GigabitEthernet3/0/7, Giriş Hataları: 213, Çıkış Hataları: 12

Ziyaret edilen tüm cihazlar:
- 10.20.4.137
- 10.20.4.138
- 10.20.4.139
...
```

## Sorun Giderme

PySnmp kütüphanesi ile ilgili import sorunları yaşıyorsanız:

1. Kütüphaneleri kaldırın:
```
pip uninstall pysnmp pyasn1
```

2. Uyumlu sürümleri yükleyin:
```
pip install pyasn1==0.4.8
pip install pysnmp==4.4.12
```

## Notlar

- Bu script için SNMP v2c kullanılmaktadır.
- Switch'lerde LLDP protokolünün etkinleştirilmiş olması gerekmektedir.
- Ağdaki cihazlara erişim için doğru SNMP community string'inin bilinmesi gerekmektedir.

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
