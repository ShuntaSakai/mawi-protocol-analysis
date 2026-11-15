# MAWI IPプロトコル分布解析

MAWIのバックボーントラフィックを対象に、TCP/UDPに限定すると評価対象からどの通信量が外れるかを調べるため、外側IPヘッダのプロトコル分布を集計します。対象は [MAWI Samplepoint-F の 2026年4月8日 14:00以上14:15未満（JST）](https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.html) の Overall（Prefixの絞り込みなし）です。

## 実行方法

Python 3.10 以上が必要です。解析時の外部依存はありません。

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
mawi-protocol-analysis /path/to/202604081400.pcap.gz
python -m unittest discover -s tests -v
```

インストールせずに、リポジトリのルートで `python3 -m mawi_protocol_analysis /path/to/202604081400.pcap` と実行することもできます。入力は classic Ethernet PCAP（2.4、非圧縮または gzip）です。PCAPを1レコードずつ読み、パケット一覧や中間CSVは保存しません。マイクロ秒とナノ秒、リトルエンディアンとビッグエンディアンに対応します。Unix時刻で比較し、出力には JST を明記します。

## 出力

既定では `results/202604081400/` に保存します。既存の結果は上書きしません。再実行で保存先を変える場合は `--output-root` で親ディレクトリを指定してください。

| ファイル | 内容 |
| --- | --- |
| `protocol_counts.csv` | IPバージョン・プロトコル番号別の件数、2種類のバイト数、構成比、平均サイズ、毎秒値。非IPと判定不能も独立した行に残します。 |
| `protocol_timeseries_60s.csv` | 出現した分類ごとに15個の1分区間の件数とバイト数を出力します。該当なしの区間は0です。分類が一つもない場合はヘッダのみになり、区間は `summary.json` に残ります。 |
| `summary.json` | Overall・IPv4・IPv6などの合計、時間区間、除外数、判定不能や長さ未取得の理由。 |
| `manifest.json` | 入力ファイル情報、リンクタイプ、snaplen、FCSの宣言、集計定義、プログラムと実行環境のバージョン。 |

区間はすべて開始を含み終了を含みません。構成比（0～1）の分母は、`_overall` が有効な時間内レコードすべて、`_ip_version` がそのIPv4またはIPv6全体です。バイト構成比は対応するバイト数の合計を使い、IPバイト構成比はIP長を取得できたパケットだけを分母に含めます。平均サイズも、元フレーム長は全パケット、IP長は取得できたパケットで割ります。分母が0ならCSVでは空欄、JSONでは `null` です。全期間の毎秒値は900秒、Notebookで1分の毎秒値を求める場合は60秒を使います。

`non_tcp_udp_packets` は、番号を判定できたIPv4/IPv6のうち TCP・UDP 以外の件数です。プロトコル判定不能と非IPは別に数えます。

- **`original_frame_bytes`（主指標）**：PCAPレコードヘッダの `orig_len` の合計。EthernetとVLANのヘッダを含みます。FCSの有無は観測条件に依存し、物理回線上の総転送量を表す指標ではありません。
- **`ip_packet_bytes`（補助指標）**：IPv4の Total Length、または IPv6の40バイト＋Payload Length。宣言長が元フレームに収まるか確認し、取得可能な長さのみ合計します。長さを取得できない件数はプロトコル判定不能とは別に記録し、非IPはIP長の取得対象外です。保存長 `incl_len` はいずれの通信量にも使いません。

## 解析上の制約

Ethernet II と VLAN タグ（0x8100、0x88a8、0x9100）を読み、IPv4は外側の Protocol、IPv6は Hop-by-Hop、Routing、Destination Options、Fragment、AHをたどった Next Header で分類します。ESPで探索を止め、GREやIPトンネルの内部は解析しません。番号は保持し、代表的な名称は [IANAの登録](https://www.iana.org/assignments/protocol-numbers/) を参照します。フラグメントは分類と重複する属性です。再構成は行わず、IPv6の後続フラグメントで拡張ヘッダをたどれない場合は判定不能とします。IPv6のatomic fragment（オフセット0かつM=0）はフラグメント件数に含めません。

対象外の時刻や、不正なレコードは除外理由を記録します。読み切れないレコードや未対応のファイル形式では、解析を中断します。キャプチャされたヘッダで判定できない場合は、その理由と取得できた通信量を保持します。IPv6 Jumbo Payload、その他の未対応拡張ヘッダ、Ethernet IEEE 802.3 LLC/SNAPには対応しません。トランスポートヘッダの妥当性やチェックサムは検証しません。

公開統計の `frag` は独立行であり、本実装とは分類方法に差があります。MAWI公式統計やAguriのバイト数と直接比較する際は、使用したツールと設定で集計対象・バイト定義が一致することを確認してください。この観測区間の結果を、MAWI全期間やインターネット全体には一般化しません。
