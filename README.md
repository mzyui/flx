## Fluxy 🚀

**Fluxy** (pronounced `flox-si`) is the exciting successor to `proxy.rs`. Currently in its early development stages, Fluxy is set to revolutionize proxy management.

#### Example 📝

> [!NOTE]
> On the first use, Fluxy automatically downloads **maxminddb** for geo lookup purposes.

Here's the debug output showing the proxy validator process:

```sh
 fluxy -t HTTP -l 10 --log debug -f json
fluxy::fetcher: DEBUG Proxy gathering started (27 sources)
fluxy::validator: DEBUG Proxy validator started (500 workers)
fluxy::resolver: DEBUG My IP: 114.10.152.29 (resolved in 47.73877ms)

[
  {"ip":"65.1.244.232","port":80,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.032629307749999996,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.729317}},
  {"ip":"52.196.1.182","port":80,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"13","region_name":"Tokyo","city_name":"Tokyo"},"average_response_time":0.04735451925,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.7895415}},
  {"ip":"3.37.125.76","port":3128,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.051829942500000004,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8131318}},
  {"ip":"43.200.77.128","port":3128,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.04032374975,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8233922}},
  {"ip":"13.208.56.180","port":80,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"27","region_name":"Osaka","city_name":"Osaka"},"average_response_time":0.05889850025,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8411582}},
  {"ip":"3.108.115.48","port":1080,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.071890385,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.880884}},
  {"ip":"35.79.120.242","port":3128,"geo":{"iso_code":"JP","name":"Japan","region_iso_code":"13","region_name":"Tokyo","city_name":"Tokyo"},"average_response_time":0.05932753875,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.8997948}},
  {"ip":"43.202.154.212","port":80,"geo":{"iso_code":"KR","name":"South Korea","region_iso_code":"28","region_name":"Incheon","city_name":"Incheon"},"average_response_time":0.0605324615,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798625.9165545}},
  {"ip":"13.234.24.116","port":1080,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.09377788449999999,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798626.034847}},
  {"ip":"15.206.25.41","port":3128,"geo":{"iso_code":"IN","name":"India","region_iso_code":"MH","region_name":"Maharashtra","city_name":"Mumbai"},"average_response_time":0.11225623075,"type":{"protocol":{"Http":"Elite"},"checked_on":1734798626.055605}}
]

fluxy::validator: DEBUG Proxy validator completed: 10/10542 proxies validated (1.281753231s)
fluxy::fetcher: DEBUG Proxy gathering completed: 19946 proxies found (1.488841769s)
```
