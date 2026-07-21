# CVE-2017-1000486
Remote Code Execution exploit for PrimeFaces 5.x - EL Injection (CVE-2017-1000486)

This is basically the same exploit made by [Mogwailabs](https://github.com/mogwailabs/CVE-2017-1000486), but edited to work in closed environments without access to the internet or with blocked firewall outbound traffic.
It gives you results in HTTP response header, so in case you're trying doing blind RCEwith old exploit - not anymore.

### Usage
```
python3 primefaces.py -t vulnapp.com id
```
Feel free to edit _vuln_point_ variable for exact endpoint.
