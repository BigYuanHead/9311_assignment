1. read binary file
2. parse 12-byte header
3. parse flags
4. write decode_name()
5. parse questions by QDCOUNT
6. parse one resource record
7. parse Answer section
8. parse Authority section
9. parse Additional section
10. decode A / NS / CNAME / PTR / MX RDATA
11. unsupported type 用 RDLENGTH 跳过
12. print required output