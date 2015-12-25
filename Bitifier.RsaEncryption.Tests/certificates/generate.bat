makecert -r -pe -n "CN=Test certificate A 2048" -b 01/01/2007 -e 01/01/2040 -len 2048 -sky exchange Test2048A.cer.bin -sv Test2048A.pvk.bin
pvk2pfx.exe -pvk Test2048A.pvk.bin -pi secret -spc Test2048A.cer.bin -pfx Test2048A.pfx.bin -po secret

makecert -r -pe -n "CN=Test certificate B 2048" -b 01/01/2007 -e 01/01/2040 -len 2048 -sky exchange Test2048B.cer.bin -sv Test2048B.pvk.bin
pvk2pfx.exe -pvk Test2048B.pvk.bin -pi secret -spc Test2048B.cer.bin -pfx Test2048B.pfx.bin -po secret

makecert -r -pe -n "CN=Test certificate 4096" -b 01/01/2007 -e 01/01/2040 -len 4096 -sky exchange Test4096A.cer.bin -sv Test4096A.pvk.bin
pvk2pfx.exe -pvk Test4096A.pvk.bin -pi secret -spc Test4096A.cer.bin -pfx Test4096A.pfx.bin -po secret