## Random Packetloss

**指定した確率でパケットを破棄するeBPFプログラム**

### 必要な環境 (Prerequisites)

このプログラムをビルド・実行するには、以下のツールと環境が必要です。

*   **Go**: 1.23以上
*   **Clang / LLVM**: eBPFプログラムのコンパイル用
*   **Linuxカーネルヘッダー**: eBPFプログラムのコンパイル用

```shell
sudo apt update
sudo apt install -y golang-go clang llvm linux-headers-$(uname -r) libbpf-dev
```

### ビルド (Build)

eBPFプログラムをコンパイルする

```shell
$ clang -target bpf -I/usr/include/$(uname -m)-linux-gnu -g -O2 -c random_packetloss.bpf.c -o random_packetloss.bpf.o
```

アタッチするネットワークインタフェースと、パケットを破棄する確率を決める
```shell
$ sudo go run main.go -iface <network-interface> -rate <rate>
```

例: 30%の確率でパケットを破棄するプログラムをwlp1s0にアタッチする
```shell
$ sudo go run main.go -iface wlp1s0 -rate 30
```