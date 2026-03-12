# PROJE RAPORU

## SDN Tabanlı Otomatik Tehdit Tespiti ve Müdahale Sistemi

## 1. Giriş

Bu proje kapsamında, yazılım tanımlı ağ yaklaşımını kullanarak ağ trafiğini merkezi olarak yöneten, şüpheli hareketleri tespit eden ve saldırılara otomatik olarak karşılık verebilen bir güvenlik altyapısı geliştirilmiştir. Çalışmanın temel amacı, klasik ağlarda insan müdahalesine bağlı kalan saldırı tespit ve engelleme süreçlerini olabildiğince otomatik hale getirmektir.

Sistem bir proof-of-concept olarak tasarlanmıştır. Sanal bir kurumsal ağ ortamı, SDN denetleyicisi ve saldırı tespit sistemi ile birleştirilmiş; böylece saldırı algılama ile ağ seviyesinde yaptırım uygulama tek bir zincir içinde toplanmıştır.

## 2. Projenin Amacı

Projede hedeflenen başlıca kazanımlar şunlardır:

- Kurumsal bir ağı temsil eden örnek bir topolojiyi yazılım tanımlı ağ mantığıyla kurmak.
- Ağın omurga noktasında merkezi görünürlük sağlamak.
- SYN flood ve port scan gibi temel tehditleri otomatik olarak algılamak.
- Tespit edilen tehdide göre uygun aksiyonu, OpenFlow kuralları üzerinden ağa anında uygulamak.
- Saldırı sona erdiğinde sistemin tekrar normal çalışma durumuna dönebilmesini sağlamak.

Bu yönüyle proje yalnızca bir ağ kurulum çalışması değil, aynı zamanda tespit, karar ve yaptırım katmanlarını bir araya getiren bütünleşik bir güvenlik otomasyonu örneğidir.

## 3. Sistem Mimarisi

Projede üç temel bileşen birlikte çalışmaktadır:

### 3.1. Ağ Topolojisi

Topoloji, kurumsal bir ağı temsil edecek şekilde tasarlanmıştır. Yapıda omurga katmanı, erişim katmanı, veri merkezi kaynakları ve dış ağdan gelebilecek trafiği temsil eden istemciler yer almaktadır.

Bu kurgu sayesinde internet tarafı, kullanıcı ağı, kurumsal servisler ve kritik sunucu segmentleri aynı ortam içinde gözlemlenebilmekte; hem normal trafik hem de saldırı senaryoları birlikte değerlendirilebilmektedir.

### 3.2. Ağın Mantıksal Ayrıştırılması

Ağ, farklı güvenlik bölgeleri oluşturacak şekilde mantıksal olarak ayrıştırılmıştır. Bu yaklaşım, aynı altyapı üzerinde farklı trafik tiplerini birbirinden ayırmayı ve güvenlik politikalarını daha kontrollü biçimde uygulamayı mümkün hale getirmiştir.

### 3.3. İzleme ve Tespit Katmanı

Ağ trafiği izleme katmanında görünür hale getirilmiş ve IDS tarafından analiz edilmiştir. Bu katman, şüpheli trafik desenlerini tespit ederek güvenlik karar mekanizmasına alarm üretmektedir. Böylece ağ görünürlüğü ile otomatik müdahale mantığı aynı mimari içinde birleştirilmiştir.

### 3.4. SDN Denetim Katmanı

SDN denetleyicisi, ağdaki yönlendirme ve güvenlik kararlarını merkezi olarak yönetmektedir. Denetleyici iki temel görevi yerine getirir:

- Normal trafikte ağ iletişimini düzenlemek.
- Tespit edilen tehditlere karşı uygun ağ politikasını devreye almak.

## 4. Sistemin Çalışma Prensibi

## 4.1. Çalışma Akışı

Sistem başlatıldığında ağ ortamı hazırlanmakta, denetleyici devreye alınmakta, izleme katmanı etkinleştirilmekte ve saldırı senaryolarının gözlemlenebileceği bir çalışma düzeni oluşturulmaktadır. Bu otomasyon, demo ve test süreçlerinde kurulum adımlarının tutarlı biçimde tekrar edilebilmesini sağlamaktadır.

## 4.2. Normal Trafik Yönetimi

Denetleyici, ağın günlük iletişim ihtiyaçlarını karşılayacak şekilde trafiği merkezi mantıkla yönlendirir. Böylece sistem yalnızca saldırı anında tepki veren bir yapı değil, aynı zamanda normal ağ hizmetlerini sürdüren işlevsel bir SDN altyapısı olarak çalışır.

## 4.3. Saldırı Tespit Mekanizması

Projede saldırı tespiti, ağ trafiğini analiz eden IDS katmanı üzerinden gerçekleştirilmektedir. Bu katman özellikle hizmet engelleme girişimleri ve tarama davranışları gibi tipik ağ tehditlerini hedef almaktadır.

Tespit edilen olaylar alarm olarak güvenlik karar mekanizmasına aktarılır. Böylece tehdit analizi ile ağ düzeyinde yaptırım uygulama süreci birbirine bağlı ve otomatik hale getirilmiştir.

## 4.4. Karar ve Yaptırım Mekanizması

Sistem her saldırı tipine aynı tepkiyi vermez. Bu proje açısından önemli olan nokta, tehdidin niteliğine göre farklı yaptırım politikalarının uygulanmasıdır.

- Yoğun trafik üreten saldırılarda hız sınırlama uygulanabilir.
- Keşif ve tarama karakteri taşıyan saldırılarda engelleme uygulanabilir.

Bu yaklaşım, her olay için aynı sertlikte tepki vermek yerine tehdidin yapısına göre ölçülü ve hedefli bir müdahale sunar.

## 4.5. Ağ Düzeyinde Önleme

Tehdit tespit edildiğinde denetleyici, ağ cihazlarına yeni kurallar göndererek ilgili trafiği sınırlandırır veya engeller. Böylece güvenlik kararı doğrudan ağ davranışına yansıtılır ve manuel müdahale ihtiyacı azaltılır.

Bu yöntem, tehditlere uç noktalarda değil ağın kontrol noktalarında müdahale edilmesini sağlar. Sonuç olarak savunma daha merkezi, daha hızlı ve daha yönetilebilir hale gelir.

## 4.6. Zaman Aşımı ve Normalleşme

Uygulanan güvenlik kuralları kalıcı değildir. Belirli bir süre boyunca etkin kalan bu kurallar daha sonra otomatik olarak kaldırılabilir. Bu sayede sistem, saldırı baskısı ortadan kalktığında normal çalışma durumuna geri dönebilir.

Bu tasarım sayesinde:

- Saldırgan sonsuza kadar bloklu kalmaz.
- Aynı kaynak saldırıya devam ederse yaptırım yeniden devreye alınabilir.
- Geçici saldırı durumlarında ağ normal çalışma durumuna otomatik döner.

## 5. Kullanılan Teknolojiler

Projede aşağıdaki başlıca teknolojilerden yararlanılmıştır:

- Python
- SDN denetleyici altyapısı
- Sanal ağ emülasyonu
- OpenFlow tabanlı kural yönetimi
- Ağ saldırı tespit sistemi
- Trafik üretimi ve test araçları
- Otomatik test araçları

Bu teknoloji seçimi, hem ağ emülasyonu hem de güvenlik otomasyonu açısından düşük maliyetli ve tekrarlanabilir bir geliştirme ortamı sunmuştur.

## 6. Gerçekleştirilen Testler

## 6.1. Birim Testleri

Projede yalnızca elle yapılan demo testleri değil, temel bileşenleri doğrulayan birim testleri de bulunmaktadır.

Projede, alarm işleme ve yaptırım uygulama zincirinin tutarlı çalıştığını doğrulayan birim testleri bulunmaktadır. Bu testler özellikle şu alanlara odaklanmaktadır:

- Algılanan olayların doğru tehdit sınıfına dönüştürülmesi
- Tehdit tipine uygun yaptırım kararının seçilmesi
- Hatalı veya beklenmeyen veri durumlarında sistemin kararlı kalması
- Ağ cihazlarına gönderilecek güvenlik kurallarının doğru mantıkla oluşturulması

Bu testler, karar ve yaptırım zincirinin en kritik kısımlarını izole biçimde doğrulamaktadır.

## 6.2. Demo Senaryoları

Demo akışında iki temel saldırı senaryosu test edilmektedir:

1. Hizmet aksatmaya yönelik yoğun trafik üretimi.
2. Ağ keşfine yönelik tarama davranışı.

Bu saldırılar başlatıldığında beklenen akış şu şekildedir:

1. Saldırı trafiği omurgadan geçer.
2. Trafik izleme katmanı tarafından analiz edilir.
3. Uygun tehdit davranışı görüldüğünde alarm üretilir.
4. Denetleyici tehdit türüne göre sınırlama veya engelleme uygular.
5. Ağ davranışındaki değişim gözlemlenerek önlemin etkisi doğrulanır.

## 7. Sonuç

Bu proje ile SDN yaklaşımının ağ güvenliğinde ne kadar etkili biçimde kullanılabileceği gösterilmiştir. Geliştirilen sistem, trafiği merkezi olarak görebilen, IDS alarmını yorumlayabilen ve aynı anda ağ cihazlarına otomatik yaptırım uygulayabilen bir güvenlik mimarisi sunmaktadır.

Elde edilen başlıca sonuçlar şunlardır:

- Kurumsal ağı temsil eden sanal bir topoloji başarıyla kurulmuştur.
- Suricata ile saldırı tespiti otomatik hale getirilmiştir.
- Ryu üzerinden OpenFlow kuralları dinamik olarak uygulanmıştır.
- Tehdit türüne göre farklı savunma politikaları geliştirilebilmiştir.
- Yaptırımlar süreli olduğu için sistem kalıcı kilitlenmelere yol açmadan çalışabilmektedir.

Sonuç olarak çalışma, modern ağlarda güvenlik kararlarının merkezi denetim mantığı ile otomatikleştirilebileceğini göstermektedir. Bu yapı daha ileri aşamada gerçek zamanlı gösterge panelleri, daha fazla saldırı imzası, makine öğrenmesi tabanlı anomali tespiti ve çoklu omurga anahtarı desteği ile genişletilebilir.
