


import telebot
from telebot import TeleBot, types
import time
import urllib.request
import urllib.parse
from urllib.parse import quote
import requests
import json
import base64
import os
import random
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from retrying import retry
from requests.exceptions import ConnectionError
import subprocess
import platform
bot = telebot.TeleBot("token")
ips=["162.159.193.96:878", "162.159.193.133:894","162.159.195.54:894","162.159.192.65:894","162.159.192.3:908","162.159.195.166:878","162.159.195.7:894", "162.159.192.214:894","162.159.193.84:878"]
ipsv6=["[2606:4700:d0::6996:c14:bcb0:b1d2]:878","[2606:4700:d1::a4b9:95c0:37ca:601e]:878","[2606:4700:d0::7050:964d:9980:9067]:878","[2606:4700:d0::cfcb:5601:66a:e8e8]:878","[2606:4700:d0::45dd:b927:8c4d:ceec]:878","[2606:4700:d1::d3f:23c9:46fc:c876]:878"]
name=""
temphi={
  "outbounds":
  [


            
        {
            "type": "wireguard",
            "server": "",
            "server_port": 0,
            "local_address": [
                "172.16.0.2/32",
                ""
            ],
            "private_key": "",
            "peer_public_key": "",
            "reserved": [],
            "mtu": 1300,
            "workers": 2,
            "detour": "",
            "tag": "",
            "fake_packets": "1-3",
            "fake_packets_size": "10-30",
            "fake_packets_delay": "10-30",
            "fake_packets_mode": "m4"
        }
  ]
}
temp2hi={
  "outbounds":
  [


            
        {
            "type": "wireguard",
            "server": "",
            "server_port": 0,
            "local_address": [
                "172.16.0.2/32",
                ""
            ],
            "private_key": "",
            "peer_public_key": "",
            "reserved": [],
            "mtu": 1300,
            "workers": 2,
            "detour": "",
            "tag": "",
            "fake_packets_mode": "m4"
        }
  ]
}

temp={
  "outbounds":
  [
        {
            "type": "wireguard",
            "server": "",
            "server_port": 0,
            "local_address": [
                "172.16.0.2/32",
                ""
            ],
            "private_key": "",
            "peer_public_key": "",
            "reserved": [],
            "mtu": 1330,
            "workers": 2,
            "detour": "",
            "tag": ""
        }
  ]
}
temp2={
  "outbounds":
  [
        {
            "type": "wireguard",
            "server": "",
            "server_port": 0,
            "local_address": [
                "172.16.0.2/32",
                ""
            ],
            "private_key": "",
            "peer_public_key": "",
            "reserved": [],
            "mtu": 1330,
            "workers": 2,
            "detour": "",
            "tag": ""
        }
  ]
}
true=True
WoW_v2={
        "remarks": "Tel= arshiacomplus - WoW",
        "log": {
            "loglevel": "warning"
        },
        "dns": {
            "hosts": {},
            "servers": [
                "https://94.140.14.14/dns-query",
                {
                    "address": "8.8.8.8",
                    "domains": [
                        "geosite:category-ir",
                        "domain:.ir"
                    ],
                    "expectIPs": [
                        "geoip:ir"
                    ],
                    "port": 53
                }
            ],
            "tag": "dns"
        },
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                    "userLevel": 8
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls"
                    ],
                    "enabled": true,
                    "routeOnly": true
                },
                "tag": "socks-in"
            },
            {
                "port": 10809,
                "protocol": "http",
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                    "userLevel": 8
                },
                "sniffing": {
                    "destOverride": [
                        "http",
                        "tls"
                    ],
                    "enabled": true,
                    "routeOnly": true
                },
                "tag": "http-in"
            },
            {
                "listen": "127.0.0.1",
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "1.1.1.1",
                    "network": "tcp,udp",
                    "port": 53
                },
                "tag": "dns-in"
            }
        ],
        "outbounds": [
            {
                "protocol": "wireguard",
                "settings": {
                    "address": [
                        "172.16.0.2/32",
                        ""
                    ],
                    "mtu": 1280,
                    "peers": [
                        {
                            "endpoint": "",
                            "publicKey": ""
                        }
                    ],
                    "reserved":0 ,
                    "secretKey": "",
                    "keepAlive": 10,
                    "wnoise": "quic",
                    "wnoisecount": "10-15",
                    "wpayloadsize": "1-8",
                    "wnoisedelay": "1-3"
                },
                "streamSettings": {
                    "sockopt": {
                        "dialerProxy": "warp-ir"
                    }
                },
                "tag": "warp-out"
            },
            {
                "protocol": "wireguard",
                "settings": {
                    "address": [
                        "172.16.0.2/32",
                        ""
                    ],
                    "mtu": 1280,
                    "peers": [
                        {
                            "endpoint": "162.159.192.115:864",
                            "publicKey": ""
                        }
                    ],
                    "reserved": 0,
                    "secretKey": "",
                    "keepAlive": 10,
                    "wnoise": "quic",
                    "wnoisecount": "10-15",
                    "wpayloadsize": "1-8",
                    "wnoisedelay": "1-3"
                },
                "tag": "warp-ir"
            },
            {
                "protocol": "dns",
                "tag": "dns-out"
            },
            {
                "protocol": "freedom",
                "settings": {},
                "tag": "direct"
            },
            {
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                },
                "tag": "block"
            }
        ],
        "policy": {
            "levels": {
                "8": {
                    "connIdle": 300,
                    "downlinkOnly": 1,
                    "handshake": 4,
                    "uplinkOnly": 1
                }
            },
            "system": {
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "inboundTag": [
                        "dns-in"
                    ],
                    "outboundTag": "dns-out",
                    "type": "field"
                },
                {
                    "ip": [
                        "8.8.8.8"
                    ],
                    "outboundTag": "direct",
                    "port": "53",
                    "type": "field"
                },
                {
                    "domain": [
                        "geosite:category-ir",
                        "domain:.ir"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": [
                        "geoip:ir",
                        "geoip:private"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "outboundTag": "warp-out",
                    "type": "field",
                    "network": "tcp,udp"
                }
            ]
        },
        "stats": {}
    }


def get_ip():
    lst_none=[]

    @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
    def file_o():

                response = requests.get("https://raw.githubusercontent.com/arshiacomplus/WoW-fix/main/Bestip2.txt", timeout=30)
                return response.text
            
    response = file_o()
    tmp=""
    for i in response:
        
        if i =="\n":
            lst_none.append(tmp)
            tmp=""
        else:
              tmp+=i

    return lst_none

def arch_suffix():
    machine = platform.machine().lower()
    if machine.startswith('i386') or machine.startswith('i686'):
        return '386'
    elif machine.startswith(('x86_64', 'amd64')):
        return 'amd64'
    elif machine.startswith(('armv8', 'arm64', 'aarch64')):
        return 'arm64'
    elif machine.startswith('s390x'):
        return 's390x'
    else:
        raise ValueError("Unsupported CPU architecture")
def export_bestIPS(path):
    Bestip = []

    with open(path, 'r') as csv_file:
        next(csv_file)
        c = 0
        for line in csv_file:
            Bestip.append(line.split(',')[0])
            c += 1
            if c == 2:
                break

    with open('Bestip.txt', 'w') as f:
        for ip in Bestip:
            f.write(f"{ip}\n")

    return Bestip
def byte_to_base64(myb):
    return base64.b64encode(myb).decode('utf-8')
     

def generate_public_key(key_bytes):
    # Convert the private key bytes to an X25519PrivateKey object
    private_key = X25519PrivateKey.from_private_bytes(key_bytes)
    
    # Perform the scalar multiplication to get the public key
    public_key = private_key.public_key()
    
    # Serialize the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )    
    return public_key_bytes



def generate_private_key():
    key = os.urandom(32)    
    # Modify random bytes using algorithm described at:
    # https://cr.yp.to/ecdh.html.
    key = list(key) # Convert bytes to list for mutable operations
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64    
    return bytes(key) # Convert list back to bytes




def register_key_on_CF(pub_key):
    time.sleep(5)
    url = 'https://api.cloudflareclient.com/v0a4005/reg'
    # url = 'https://api.cloudflareclient.com/v0a2158/reg'
    # url = 'https://api.cloudflareclient.com/v0a3596/reg'

    body = {"key": pub_key,
            "install_id": "",
            "fcm_token": "",
            "warp_enabled": True,
            "tos": datetime.datetime.now().isoformat()[:-3] + "+07:00",
            "type": "Android",
            "model": "PC",
            "locale": "en_US"}

    bodyString = json.dumps(body)

    headers = {'Content-Type': 'application/json; charset=UTF-8',
               'Host': 'api.cloudflareclient.com',
               'Connection': 'Keep-Alive',
               'Accept-Encoding': 'gzip',
               'User-Agent': 'okhttp/3.12.1',
               "CF-Client-Version": "a-6.30-3596"
               }

    r = requests.post(url, data=bodyString, headers=headers)
    return r




def bind_keys():
    priv_bytes = generate_private_key()
    priv_string = byte_to_base64(priv_bytes)
    
    
    
    
    pub_bytes = generate_public_key(priv_bytes)
    pub_string = byte_to_base64(pub_bytes)
    
    



    result = register_key_on_CF(pub_string)
    
    if result.status_code == 200:
        try:
            z = json.loads(result.content)
            client_id = z['config']["client_id"]      
            cid_byte = base64.b64decode(client_id)
            reserved = [int(j) for j in cid_byte]
            
            
            return ['2606:4700:110:846c:e510:bfa1:ea9f:5247/128',priv_string,reserved, 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=']
            
        except Exception as e:
            print('Something went wronge with api')
            exit()


def urlencode(string):
    
    if string is None:
        return None
    return urllib.parse.quote(string, safe='a-zA-Z0-9.~_-')
def fetch_config_from_api():

    bind=bind_keys()
    return {
        'PrivateKey': bind[1],
        'PublicKey': bind[3],
        'Reserved':bind[2],
        'Address': bind[0]
    }
def generate_wireguard_url(config, ip_check,endpointv6):
    global name
    global WoW_v2
    endpoint=ip_check[0]
    required_keys = ['PrivateKey', 'PublicKey' ,'Address' ]
    if not all(key in config and config[key] is not None for key in required_keys):
        print("Incomplete configuration. Missing one of the required keys or value is None.")
        return None

    listt=config['Reserved']
    reserved_sind=config['Reserved']

    lostt2=''
    for num in range(len(listt)):
        lostt2+=str(listt[num])
        if num != len(listt)-1:
            lostt2+=','
    config['Reserved']=urlencode(lostt2)
    wireguard_urll = ("```config\n"
        f"wireguard://{urlencode(config['PrivateKey'])}@{endpoint}"
        f"?address=172.16.0.2/32, {config['Address']}&"
        f"publickey={urlencode(config['PublicKey'])}"
    )
    
    
    if config.get('Reserved'):
        wireguard_urll += f"&reserved={config['Reserved']}"
    
    wireguard_urll += "#Tel= @arshiacomplus wire ```"

    wireguard_urll2 = ("```config\n"
        f"wireguard://{urlencode(config['PrivateKey'])}@{endpointv6}"
        f"?address=172.16.0.2/32, {config['Address']}&"
        f"publickey={urlencode(config['PublicKey'])}"
    )
    
    
    if config.get('Reserved'):
        wireguard_urll2 += f"&reserved={config['Reserved']}"
    
    wireguard_urll2 += "#Tel= @arshiacomplus wire ```"
    
    wireguard_urll_nika = ("```config\n"
        f"wireguard://{urlencode(config['PrivateKey'])}@{endpoint}"
        f"?wnoise=quic&address=172.16.0.2/32,{urlencode(config['Address'])}&keepalive=10&wpayloadsize=1-8&"
        f"publickey={urlencode(config['PublicKey'])}&wnoisedelay=1-3&wnoisecount=15&mtu=1330"
    )
   #wireguard://qO6m%2BpxSH677ETSmqykciE7MQ7rp0Jw8qJHSUh7Gj3k%3D@162.159.195.166:878?wnoise=quic&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A846c%3Ae510%3Abfa1%3Aea9f%3A5247%2F128&reserved=111%2C162%2C171&keepalive=5&wpayloadsize=1-8&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&wnoisedelay=1-3&wnoisecount=15&mtu=1280#Tel%3D+%40arshiacomplus+wire
    if config.get('Reserved'):
   
                wireguard_urll_nika += f"&reserved={config['Reserved']}"
            
    
    wireguard_urll_nika+= "#Tel= @arshiacomplus wire ```"


    wireguard_urll_nika_v6 = ("```config\n"
        f"wireguard://{urlencode(config['PrivateKey'])}@{endpointv6}"
        f"?wnoise=quic&address=172.16.0.2/32,{urlencode(config['Address'])}&keepalive=10&wpayloadsize=1-8&"
        f"publickey={urlencode(config['PublicKey'])}&wnoisedelay=1-3&wnoisecount=15&mtu=1330"
    )
   #wireguard://qO6m%2BpxSH677ETSmqykciE7MQ7rp0Jw8qJHSUh7Gj3k%3D@162.159.195.166:878?wnoise=quic&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A846c%3Ae510%3Abfa1%3Aea9f%3A5247%2F128&reserved=111%2C162%2C171&keepalive=5&wpayloadsize=1-8&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&wnoisedelay=1-3&wnoisecount=15&mtu=1280#Tel%3D+%40arshiacomplus+wire
    if config.get('Reserved'):
   
                wireguard_urll_nika_v6 += f"&reserved={config['Reserved']}"
            
    
    wireguard_urll_nika_v6 += "#Tel= @arshiacomplus wire ```"

    config2=fetch_config_from_api()
#     with open('sing-box-hiddify.json' , 'w') as f:
#         f.write(f'''{{
#   "outbounds":
#   [

#     {{
#     "type": "wireguard",
#     "tag": "Tel=@arshiacomplus Warp-IR1",
#     "local_address": [
#         "172.16.0.2/32",
#         "{config['Address']}"
#     ],
#     "private_key": "{config['PrivateKey']}",
#     "peer_public_key": "{config['PublicKey']}",
#     "server": "{endpoint.split(":")[0]}",
#     "server_port": {endpoint.split(":")[1]},
#     "reserved": {reserved_sind},

#     "mtu": 1330,
#     "fake_packets":"1-3",
#     "fake_packets_size":"10-30",
#     "fake_packets_delay":"10-30",
#     "fake_packets_mode":"m4"
#     }},
#     {{
#     "type": "wireguard",
#     "tag": "Tel=@arshiacomplus Warp-Main1",
#     "detour": "Tel=@arshiacomplus Warp-IR1",
#     "local_address": [
#         "172.16.0.2/32",
#         "{config2['Address']}"
#     ],
#     "private_key": "{config2['PrivateKey']}",
#     "server": "{endpoint.split(":")[0]}",
#     "server_port": {endpoint.split(":")[1]},
#     "peer_public_key": "{config2['PublicKey']}",
#     "reserved": {config2['Reserved']},
#     "mtu": 1300,
#     "fake_packets_mode":"m4"
 
#     }}
#   ]
# }}
# ''')
    conf={"outbounds":[{"type":"wireguard","tag":"Tel=@arshiacomplus Warp-IR1","local_address":["172.16.0.2/32",""],"private_key":"","peer_public_key":"","server":"","server_port":0,"reserved":[],"mtu":1330,"fake_packets":"1-3","fake_packets_size":"10-30","fake_packets_delay":"10-30","fake_packets_mode":"m4"},{"type":"wireguard","tag":"Tel=@arshiacomplus Warp-Main1","detour":"Tel=@arshiacomplus Warp-IR1","local_address":["172.16.0.2/32",""],"private_key":"","server":"","server_port":0,"peer_public_key":"","reserved":[],"mtu":1300,"fake_packets_mode":"m4"}]}
    conf['outbounds'][0]['local_address'][1]=config["Address"]
    conf['outbounds'][0]["private_key"]=config['PrivateKey']
    conf['outbounds'][0]['peer_public_key']=config['PublicKey']
    conf['outbounds'][0]['reserved']=reserved_sind
    conf['outbounds'][0]['server']=ip_check[0].split(':')[0]
    # conf['outbounds'][0]['server']=endpoint.split(':')[0]
    conf['outbounds'][0]['server_port']=int(ip_check[1].split(':')[1])
    # conf['outbounds'][0]['server_port']=endpoint.split(':')[1]
    conf['outbounds'][1]['local_address'][1]=config2["Address"]
    conf['outbounds'][1]["private_key"]=config2['PrivateKey']
    conf['outbounds'][1]['peer_public_key']=config2['PublicKey']
    conf['outbounds'][1]['reserved']=config2['Reserved']
    conf['outbounds'][1]['server']=ip_check[1].split(':')[0]
    # conf['outbounds'][1]['server']=endpoint.split(':')[0]
    conf['outbounds'][1]['server_port']=int(ip_check[1].split(':')[1])
    # conf['outbounds'][1]['server_port']=endpoint.split(':')[1]
    conf=json.dumps(conf)

    WoW_v2["outbounds"][1]["settings"]['secretKey']=config['PrivateKey']
    WoW_v2["outbounds"][1]["settings"]["peers"][0]['publicKey']=config["PublicKey"]
    WoW_v2["outbounds"][1]["settings"]['reserved']=reserved_sind
    WoW_v2["outbounds"][1]["settings"]['address'][1]=config["Address"]
    WoW_v2["outbounds"][1]["settings"]["peers"][0]['endpoint'] = ip_check[0].split(':')[0]+":"+ip_check[1].split(':')[1]
    WoW_v2["outbounds"][1]["settings"]['mtu'] = 1300
    
    WoW_v2["outbounds"][0]["settings"]['secretKey']=config2['PrivateKey']
    WoW_v2["outbounds"][0]["settings"]["peers"][0]['publicKey']=config2["PublicKey"]
    WoW_v2["outbounds"][0]["settings"]['reserved']=config2['Reserved']
    WoW_v2["outbounds"][0]["settings"]['address'][1]=config2["Address"]
    WoW_v2["outbounds"][0]["settings"]["peers"][0]['endpoint'] = ip_check[1].split(':')[0]+":"+ip_check[1].split(':')[1]
    WoW_v2["outbounds"][0]["settings"]['mtu'] =1300

    WoW_v3=json.dumps(WoW_v2)



    conf.replace("'", '"')
    name=f"warp{random.randint(1,10000)}.conf"
    with open(name, "w") as f:
        f.write(f'''[Interface]
PrivateKey = {config['PrivateKey']}
Address = 172.16.0.2/32, {config2["Address"]}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1330

[Peer]
PublicKey = {config['PublicKey']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {ip_check[0].split(':')[0]}:{int(ip_check[1].split(':')[1])}''')
    with open("wg_"+name, "w") as f:
        f.write(f'''[Interface]
Address = 172.16.0.2/32, {config2["Address"]}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
H1 = 1
H2 = 2
H3 = 3
H4 = 4
PrivateKey =  {config['PrivateKey']}

[Peer]
PublicKey = {config['PublicKey']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {ip_check[0].split(':')[0]}:{int(ip_check[1].split(':')[1])}''')
    return "For [[mahsaNg](https://github.com/GFW-knocker/MahsaNG/releases) , [nikaNg](https://github.com/mahsanet/NikaNG/releases) ] ng without noise: \U0001FAF5 \n\nipv4: \U0001F97A\n\n"+wireguard_urll+"\n\nipv6: \U0001F97A\n\n"+ wireguard_urll2+"\n\n For [[mahsaNg](https://github.com/GFW-knocker/MahsaNG/releases) , [nikaNg](https://github.com/mahsanet/NikaNG/releases) ] ng with noise: \U0001FAF5"+" \n\nipv4: \U0001F97A\n\n"+wireguard_urll_nika+"\n\nipv6:  \U0001F97A \n\n"+ wireguard_urll_nika_v6+ "\n\nFor [hiddify](https://github.com/hiddify/hiddify-next/releases) next: \U0001FAF5 "+f'```js\n\n{conf}``` \n\n ```ipv4\n\nwarp://{ip_check[0]}/?ifp=1-3&ifpm=m4#IR&&detour=warp://{ip_check[1]}/?ifp=1-3&ifpm=m5#DE```\n```ipv6\nwarp://{endpointv6}/?ifp=1-3&ifpm=m4#IR&&detour=warp://{endpointv6}/?ifp=1-3&ifpm=m5#DE\n```'+"\n\nMainChannel= [@arshia_mod_fun](tg://user?id=2093246093) \U0001F977\nChannel= @warpscanner \U0001F977" ,"\n\n For Xray cores [[mahsaNg](https://github.com/GFW-knocker/MahsaNG/releases) , [nikaNg](https://github.com/mahsanet/NikaNG/releases) ]\n\n"+f"```js \n {WoW_v3}``` "



@bot.message_handler(commands=['start', 'help','stop'])
def send_welcome(message):
    if message.chat.type != 'private':
        return
    while True:
        ## ip=ips[random.randint(0,8)]
        #arch = arch_suffix()
        #script_dir = os.path.dirname(__file__)
        #print("Fetch warp program...")
        #url = f"https://gitlab.com/Misaka-blog/warp-script/-/raw/main/files/warp-yxip/warp-linux-{arch}"
        #subprocess.run(["wget", url, "-O", "warp"])
        #os.chmod("warp", 0o755)
        #command = "./warp >/dev/null 2>&1"
        #print("Scanning ips...")
        #process = subprocess.Popen(command, shell=True)
        #process.wait()
        #if process.returncode != 0:
            #print("Error: Warp execution failed.")
        #else:
            #print("Warp executed successfully.")
        
        #result_path = os.path.join(script_dir, 'result.csv')
        #top_ips = export_bestIPS(result_path)
        #os.remove("result.csv")
        #os.remove("warp")
    
        ip=get_ip()

        ipv6=ipsv6[random.randint(0,5)]
        config=fetch_config_from_api()
        markup=types.InlineKeyboardMarkup(row_width=2)
        button1=types.InlineKeyboardButton("Github",url="https://github.com/arshiacomplus")
        button2=types.InlineKeyboardButton("Author",url="https://t.me/arshiacomplus")
        button3=types.InlineKeyboardButton("MahsaNG",url="https://github.com/GFW-knocker/MahsaNG/releases")
        button4=types.InlineKeyboardButton("Nikang",url="https://github.com/mahsanet/NikaNG/releases")
        button5=types.InlineKeyboardButton("Hiddify",url="https://github.com/hiddify/hiddify-next/releases")
        markup.add(button1 , button2, button3 , button4,button5)
        ad1 , ad2=generate_wireguard_url(config,ip,ipv6)
        bot.send_sticker("@warpscanner","CAACAgQAAxkBAX2LwWbTdiwXZXzPjxZKNB04_TJsbqvDAALMGQACKleAUpsBJkSR_3eKNQQ")
        bot.send_message("@warpscanner",ad1 ,parse_mode='Markdown',reply_markup=markup)
        bot.send_sticker("@warpscanner","CAACAgQAAxkBAX2LwWbTdiwXZXzPjxZKNB04_TJsbqvDAALMGQACKleAUpsBJkSR_3eKNQQ")
        bot.send_message("@warpscanner",ad2,parse_mode='Markdown',reply_markup=markup)
        with open(name, "rb") as f:
             
            bot.send_document("@warpscanner",f,caption="for WireGuard :/  \U0001FAF5")
        with open("wg_"+name, "rb") as f:
             
            bot.send_document("@warpscanner",f,caption="for WgTunnel :/  \U0001FAF5")

        # with open("sing-box-hiddify.json", "rb") as file :
        #     bot.send_document("@warpscanner",file,caption="کانفیگ برای هیدیفای \U0001F97A")
        os.remove(name)
        os.remove("wg_"+name)
        time.sleep(3600*8)
        
print("Made with love by @Arshiacomplus")

bot.infinity_polling()

# Made with love by @ArshiaComplus
