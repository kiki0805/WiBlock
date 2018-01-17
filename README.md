# WiBlock

Wi-Fi authentication based on blockchain.

## Features

- 认证钱包公秘钥生成
- 交易签名认证、生成接口
- 区块链挖矿、共识接口


## Design

### 区块链节点

- 任何一个区块链节点客户端都可以作为 WiBlock 服务端
- `python server.py -p server_port`


### AP 客户端

- 运行在 AP 上的程序，用于 STA 成功接入网络之前和区块链节点交流的中介。
- `python client4AT.py -p server_port -s server_ip`


### STA 客户端

- 运行在 STA 上的程序，用于连接 Wi-Fi 前的交易确认和签名；连接后的交易广播确认。
- `python client4STA.py -p server_port -s server_ip -k AP_ip`


## Todo

- 结合硬件连接
	- https://github.com/oblique/create_ap
- 规范数据包格式，适应多平台
- 交易广播
- 256位秘钥生成
- STA 连入后交易广播验证的完善
	- 当前账本找不到的话，继续查询 blockchain
- Authcoin 丢失后重新申请


## Environment

- `docker pull kiki0805/python_web`


## Reference

- http://ieeexplore.ieee.org/document/7800479/
- Sanda, Tomoyuki, and H. Inaba. "Proposal of new authentication method in Wi-Fi access using Bitcoin 2.0." Consumer Electronics, 2016 IEEE, Global Conference on IEEE, 2016:1-5.
