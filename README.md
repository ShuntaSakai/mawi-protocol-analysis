# MAWI IPプロトコル分布解析

MAWIのバックボーントラフィックを対象に、TCP/UDPに限定すると評価対象からどの通信量が外れるかを調べるため、外側IPヘッダのプロトコル分布を集計します。対象は [MAWI Samplepoint-F の 2026年4月8日 14:00以上14:15未満（JST）](https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.html) の Overall（Prefixの絞り込みなし）です。

## 実行方法

Python 環境は uv で管理します。macOS と Linux では公式インストーラを使えます。macOS で Homebrew を利用している場合は `brew install uv` でも導入できます。[uv のインストール方法](https://docs.astral.sh/uv/getting-started/installation/)

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

リポジトリのルートで `uv sync --locked` を実行すると、`.python-version` で指定した Python 3.12 の仮想環境 `.venv` が作成され、`uv.lock` に従って解析パッケージがインストールされます。解析時の外部依存はありません。`uv run` が仮想環境を使うため、通常は手動で有効化する必要はありません。

```sh
uv sync --locked
uv run --locked mawi-protocol-analysis /path/to/202604081400.pcap.gz
uv run --locked python -m unittest discover -s tests -v
```

`uv run --locked python -m mawi_protocol_analysis /path/to/202604081400.pcap` と実行することもできます。入力は classic Ethernet PCAP（2.4、非圧縮または gzip）です。PCAPを1レコードずつ読み、パケット一覧や中間CSVは保存しません。マイクロ秒とナノ秒、リトルエンディアンとビッグエンディアンに対応します。Unix時刻で比較し、出力には JST を明記します。

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

IPv6拡張ヘッダの全体が保存されていなくても、保存された正しい位置の Next Header が TCP・UDP・ESP などの終端プロトコルを直接示している場合は、その番号で集計します。Next Header の1バイトだけが取得できた場合も対象ですが、実際のTCP・UDPヘッダの取得や正常性まで確認したことは意味しません。切り詰めは `header_issue_reasons` の `ipv6_truncated_extension` と、CSVの `invalid_or_missing_header_packets` に記録します。この属性はプロトコル別件数と重複します。Next Header 自体が読めない場合や、さらに別の拡張ヘッダが続いて最終的な番号を確認できない場合は判定不能です。読み取れた拡張ヘッダ長が不正な場合も、従来どおり判定不能として記録します。

対象外の時刻や、不正なレコードは除外理由を記録します。読み切れないレコードや未対応のファイル形式では、解析を中断します。キャプチャされたヘッダで判定できない場合は、その理由と取得できた通信量を保持します。IPv6 Jumbo Payload、その他の未対応拡張ヘッダ、Ethernet IEEE 802.3 LLC/SNAPには対応しません。トランスポートヘッダの妥当性やチェックサムは検証しません。

公開統計の `frag` は独立行であり、本実装とは分類方法に差があります。MAWI公式統計やAguriのバイト数と直接比較する際は、使用したツールと設定で集計対象・バイト定義が一致することを確認してください。この観測区間の結果を、MAWI全期間やインターネット全体には一般化しません。

## Jupyter Notebook で可視化

Notebook を使う場合は、リポジトリのルートで任意依存 `notebook` を含めて同期します。

```sh
uv sync --locked --extra notebook
uv run --locked --extra notebook jupyter notebook notebook/01_overall_protocol_distribution.ipynb
```

[Notebook](notebook/01_overall_protocol_distribution.ipynb) は Task 1 の CSV 2ファイルと JSON 2ファイルを `results/202604081400/` から読み込みます。別の場所にある場合は冒頭の `RESULTS_DIR` を変更してください。設定セルを編集したあと、カーネルを再起動して全セルを上から実行します。

冒頭で対象IPバージョン、表示するプロトコル番号、Others の閾値、並べ替え、時系列の構成比指標、図のサイズを変更できます。`BYTE_METRIC` の既定値は PCAP の元フレーム長（`original_frame_bytes`）です。`ip_packet_bytes` に切り替えると、取得できたIP長の合計を使います。人工データで実行する際は、図と概要の `DATA_LABEL` に出典を明記します。

画像を保存する場合は `SAVE_FIGURES = True` に設定します。結果ディレクトリ内の `figures/` に4枚のPNGを保存します。Notebookを含めたテストは `uv run --locked --extra notebook python -m unittest discover -s tests -v` で実行します。

図2の後に、60秒×15区間のプロトコル構成比の最大・最小（%）と変動幅（最大−最小、pp）を要約表で表示します。詳細表には極値を記録した開始時刻（同率は全区間、JST）と、有効・未定義区間数を表示します。IPv4/IPv6の同番号は合算し、Others集約前の番号別で計算します。TCP・UDP・ICMP・ESP・ICMPv6・GREは未出現でも表示します。

両指標を毎回算出し、バイト指標は `BYTE_METRIC` にかかわらず `original_frame_bytes`（PCAP `orig_len`）です。分母は区間ごとの選択した全IPのパケット数・元フレーム長合計で、プロトコル判定不能IPも含み、非IP・IPバージョン不明は除きます。既定の `IP_VERSION = "both"` でOverallのIPv4＋IPv6が対象です。分母0は未定義として極値から除外し、全区間未定義なら最大・最小・幅も未定義です。計算値は丸めず、表示のみ小数点以下2桁です。

`SAVE_RATIO_TABLES = True` にすると、結果ディレクトリの `tables/protocol_ratio_variation_60s_<IP_VERSION>_<一意の文字列>/` に `protocol_ratio_variation_60s.csv`（要約）、`protocol_ratio_variation_60s_details.csv`（詳細）、`metadata.json`（出典・期間・母集団・指標の定義）を保存します。CSVはフル精度の数値と英語の列名を保持し、未定義値は空欄です。再実行時は新規ディレクトリを作るため、既存結果を上書きしません。

番号別の表に加え、TCP（6）・UDP（17）・非TCP/UDPの3分類について、両指標の変動幅を比較するスライド用要約表と、最大・最小・極値時刻の詳細表を表示します。非TCP/UDPは、番号を判定できたIPパケットのうち6・17以外です。区間ごとのカウンタを合算してから構成比の極値を求め、個別プロトコルの変動幅は合算しません。判定不能IPは分母にのみ含まれるため、3分類の構成比の合計が100%未満になる場合があります。

保存時は同じ新規ディレクトリに `category_ratio_variation_60s.csv`（3分類の最大・最小・幅）と `category_ratio_variation_60s_details.csv`（極値時刻・有効/未定義区間数）を追加し、`metadata.json` に分類の定義と追加CSV名を記録します。既存の番号別CSVの列・行は変更しません。3分類も計算・CSVはフル精度、表示だけ小数点以下2桁で、分母0は極値の対象外です。
