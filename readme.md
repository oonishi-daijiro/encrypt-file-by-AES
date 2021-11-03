# AES Encrypt Any File (aeaf)



このプログラムはAESアルゴリズムでファイルを暗号化します。



### ファイルの暗号化

```
aeaf.exe enc -i cuteCat.png -key meow
```

`-i`オプションでファイルを指定し、`-key`オプションで鍵を指定します。

#### 暗号化したファイルの復号化

```
aeaf.exe dec -i cuteCat.png -key meow
```

暗号化した時と同じ鍵を指定し、復号化します。

