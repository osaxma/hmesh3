# Huawei Mesh 3 API
> A Command-line utility for communicating with Huawei Mesh 3 API


Supported features:
- Signing-in
- Reboot
- WAN detect
- Device Info

```
A Command-line utility for communicating with Huawei Mesh 3 API
Usage: dart run hmesh3.dart [options]

Example: dart run hmesh3.dart -u "username" -p "password" -i "192.168.9.103","192.168.9.106" --reboot

-u, --username       Username (typically "admin" by default)
-p, --password       Password (typically the wifi password)
-i, --ips            List of IP addresses of the routers
-r, --reboot         Reboot the routers
-w, --wan-detect     Print WAN detect output
-d, --device-info    Print Device Info
-h, --help           Display this help message
```

## Motivation:
I have been having an issue where wifi speed drops below 1Mbps for some nodes of Huawei Mesh 3. The issue seem to be resolved when a certain node is rebooted. Unfortuantely, the Huawei Mesh 3 online portal does not have an option for auto-reboot. Although, my main router (Huawei 5G CPE Pro - H122-373) includes this option and I have Link+ activated, I don't believe the auto-reboot configuration is applied to the mesh nodes by Link+.

Long story short, I wrote this program so I can automatically reboot the Huawei Mesh 3 nodes programitcally. 

## Notes
This may work with other Huawei routers, but it seems each one has its own subtle differences, whether in the API itself or the authentication protocol.

## Credits:
- https://github.com/quzard/HW-TC7102/
- https://gist.github.com/RazZziel/e10672e2ec208ab8cf4d431ab1e716c9