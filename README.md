# portscan

Задача по протоколам интернет
1) выводи список TCP/UDP 
2) Многопоточность в модуле main для проверки каждого порта выноситься поток
3) Попытка сделать определение протокола (весь модуль packegeFactory) IMAP/POP3/DNS/SMTP (возможно некоторые работают не очень)


### Работа
```
portscan.py [-h] [-t] [-u] [-p PORTS PORTS] host
```

### Примеры работы
```
(venv) C:\Users\Loliconshik\PycharmProjects\pr>python portscan.py -u --port 53 54 8.8.8.8
UDP port : 54  is open
UDP port : 53  is open DNS

(venv) C:\Users\Loliconshik\PycharmProjects\pr>python portscan.py -u -t --port 108 111 pop.masterhost.ru
UDP port : 108  is open
UDP port : 109  is open
UDP port : 110  is open
UDP port : 111  is open
TCP port : 110  is open POP3

```
