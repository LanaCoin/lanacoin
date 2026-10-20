## Lanacoin is a Pow/PoS personalized cryptocurrency
- Ticker: LANA

- Type: PoW/PoS hybrid

- PoW algorithm: sha256d

- PoS block hashing: sha256d

- Max Coins: 7.506.000.000 (7.5+ bilion) - this is the `MAX_MONEY` sanity limit for a single transaction output, not a hard cap on total supply (PoS 7% yearly interest has no end height)

- PoW reward: 10000 LANA (no halving)

- Last PoW block: 750000 (approx 7 years)

- PoS reward: fixed 1000 LANA + 7% (yearly)

- PoS reward halving: 525600 (approx 5 years, halving only for fixed reward, 7% stays the same)

- Minimum PoS age: 7 hours

- Maximum PoS age: unlimited

- Block time target: 5 minutes

- Difficulty retarget: every block

- Coinbase/coinstake maturity: 15 blocks (outputs become spendable after 16 confirmations)

- Transaction recommended minimum confirmations: 5

- Minimal TX fee: 100 Lanoshis (0.00000100 LANA)


P2P port: 7506

RPC port: 5706


Testnet P2P port: 17506

Testnet RPC port: 15706

Estimated coins in existence after end of pow 4.068.900.000 (very very rough estimate, depends on how many people will be staking...etc)

# Bootstrap files / chain states

* LanaCoin mainnet blockchain snapshots/chain states/bootstrap.dat: (pCloud: https://e.pcloud.link/publink/show?code=kZ3zdeZRX5fJhF63k4G0xo1d7qc8VVsejm7 )

* LanaCoin mainnet blockchain snapshots/chain states/bootstrap.da (MS OneDrive https://1drv.ms/u/s!AklKAv1s6c88dxvfcYgwPfvJj6I?e=a6Jnpw )

* LanaCoin testnet blockchain snapshots/chain states/bootstrap.dat (pCloud: http://u.pc.cd/HDOitalKif](https://e.pcloud.link/publink/show?code=kZrzdeZ3U10VHbPCH55fmz0N5sdA7qYF32X  - you need testnet $LANA email developer contact or ask on Lana telegram) 

# Developer contacts

Responsible disclosure and security contact: security@lanacoin.com

Exchanges and listing contact (digital currency exchange representatives should take note Lana is an open source network with no premine/instamine or any type of crowdfunding and no listing fee budget is awailable): listings@lanacoin.com

Developers contact: dev@lanacoin.com

Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
stable release versions of Lanacoin.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be
labeled 'stale'.

## Get in touch or stay updated:

- Forum: https://bitcointalk.org/index.php?topic=1448065

- Twitter: https://twitter.com/LanaCoin

- Web: https://lanacoin.com/

- Web2: https://lanacoin.net

- Community web: https://lanacoin.org

- Facebook: https://www.facebook.com/LanaCoins/

- Telegram: https://t.me/LanaCoin

- Discord: https://discord.gg/YHxKAxhk

- Medium: https://medium.com/@LanaCoin/

- CoinmarketCap: https://coinmarketcap.com/currencies/lanacoin/

- Coinpaprika: https://coinpaprika.com/coin/lana-lanacoin/

- CoinGecko: https://www.coingecko.com/en/coins/lanacoin

- Blockexplorer: https://chainz.cryptoid.info/lana/

- Instagram: https://www.instagram.com/lanacoin.cryptocurrency/

- Youtube: https://www.youtube.com/channel/UC23mCMIR7ecKm3cnbOl1laA](https://www.youtube.com/@LanaCoin-LANA
  
- Twitch: https://www.twitch.tv/lanacoin

- Lbry.tv: https://lbry.tv/$/invite/@LanaCoin:2

- Reddit: https://www.reddit.com/r/BlockmasterSi

- Mobile wallet for android: https://play.google.com/store/apps/details?id=com.cryptowallet.si

## List of wallet commands

￼
* addmultisigaddress <nrequired> <'["key","key"]'> [account]
* addnode <node> <add|remove|onetry>
* addredeemscript <redeemScript> [account]
* backupwallet <destination>
* checkkernel [{"txid":txid,"vout":n},...] [createblocktemplate=false]
* checkwallet
* createrawtransaction [{"txid":txid,"vout":n},...] {address:amount,...}
* decoderawtransaction <hex string>
* decodescript <hex string>
* dumpprivkey <lanacoinaddress>
* dumpwallet <filename>
* getaccount <lanacoinaddress>
* getaccountaddress <account>
* getaddednodeinfo <dns> [node]
* getaddressesbyaccount <account>
* getbalance [account] [minconf=1]
* getbestblockhash
* getblock <hash> [txinfo]
* getblockbynumber <number> [txinfo]
* getblockcount
* getblockhash <index>
* getblocktemplate [params]
* getcheckpoint
* getconnectioncount
* getdifficulty
* getinfo
* getmininginfo
* getnettotals
* getnewaddress [account]
* getnewpubkey [account]
* getpeerinfo
* getrawmempool
* getrawtransaction <txid> [verbose=0]
* getreceivedbyaccount <account> [minconf=1]
* getreceivedbyaddress <lanacoinaddress> [minconf=1]
* getstakesubsidy <hex string>
* getstakinginfo
* getsubsidy [nTarget]
* gettransaction <txid>
* getwork [data]
* getworkex [data, coinbase]
* help [command]
* importprivkey <lanacoinprivkey> [label] [rescan=true]
* importwallet <filename>
* keypoolrefill [new-size]
* listaccounts [minconf=1]
* listaddressgroupings
* listreceivedbyaccount [minconf=1] [includeempty=false]
* listreceivedbyaddress [minconf=1] [includeempty=false]
* listsinceblock [blockhash] [target-confirmations]
* listtransactions [account] [count=10] [from=0]
* listunspent [minconf=1] [maxconf=9999999] ["address",...]
* makekeypair [prefix]
* move <fromaccount> <toaccount> <amount> [minconf=1] [comment]
* ping
* repairwallet
* resendtx
* reservebalance [<reserve> [amount]]
* sendalert <message> <privatekey> <minver> <maxver> <priority> <id> [cancelupto]
* sendfrom <fromaccount> <tolanacoinaddress> <amount> [minconf=1] [comment] [comment-to]
* sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]
* sendrawtransaction <hex string>
* sendtoaddress <lanacoinaddress> <amount> [comment] [comment-to]
* setaccount <lanacoinaddress> <account>
* settxfee <amount>
* signmessage <lanacoinaddress> <message>
* signrawtransaction <hex string> [{"txid":txid,"vout":n,"scriptPubKey":hex,"redeemScript":hex},...] [<privatekey1>,...] [sighashtype="ALL"]
* stop
* submitblock <hex data> [optional-params-obj]
* validateaddress <lanacoinaddress>
* validatepubkey <lanacoinpubkey>
* verifymessage <lanacoinaddress> <signature> <message>
* walletlock
* walletpassphrase <passphrase> <timeout> [stakingonly]
* walletpassphrasechange <oldpassphrase> <newpassphrase>

## Community created resources

- https://magical88.com/
- https://www.buylana.com/
- https://www.selllana.com/
- https://www.lana8wonder.com/
- https://www.offlinelana.org/
- https://safelana.com/
- https://100million.fun






