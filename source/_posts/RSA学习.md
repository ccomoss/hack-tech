---
title: RSA基本原理和常见攻击手法
categories: crypto
mathjax: true
date: 2023-07-20
---

## 1 基本原理

### 公私钥的产生

1. 随机选择两个不同的大质数$p$和$q$，计算$N=p \cdot q$
2. 根据欧拉函数，求得$\varphi(N)=\varphi(p)\varphi(q)=(p-1)(q-1)$
3. 选择一个小于$\varphi(N)$的整数$e$，使$e$和$\varphi(N)$互质。并求得$e$关于$\varphi(N)$的模反元素，命名为$d$，有$ed \equiv 1 \quad (mod \quad \varphi(N))$
4. 将$p$和$q$的记录销毁

此时，$(N,e)$是公钥，$(N,d)$是私钥。

### 消息加密

首先需要将消息以一个双方约定好的格式转化为一个小于$N$，且与$N$互质的整数$m$。如果消息太长，可以将消息分为几段，这也就是我们所说的块加密，后对于每一部分利用如下公式加密：
$$m^e \equiv c \quad (mod \quad N)$$

### 消息解密
利用秘钥$d$进行解密。
$$ c^d \equiv m \quad (mod \quad N) $$
## 2 攻击——模数N
### 暴力分解N
**攻击方法1：** 当N小于512 bits时，可以使用[factordb](http://factordb.com/)直接分解大整数
**攻击方法2：** 椭圆曲线分解算法（ECM），参考[The Elliptic Curve Factorization Method](https://doc.sagemath.org/html/en/reference/interfaces/sage/interfaces/ecm.html)

### p和q相差很大
此时，$p$和$q$二者之一的值很小，可以通过穷举试除来分解模数。

### p和q相差很小
首先，由于$N=pq$，则有
$$ \frac{(p+q)^2}{4} -N = \frac{(p+q)^2}{4} - pq = \frac{(p-q)^2}{4} $$
由于$p$和$q$相差很小，则$\frac{(p-q)^2}{4}$的值较小，因为$\frac{(p+q)^2}{4}$略大于$N$，故而$\frac{p+q}{2}$与$\sqrt{N}$相近。然后可以按照如下方式分解：
- 顺序检查从$\sqrt{N}$开始的每一个整数$x$，直至找到一个数满足$x^2-N$是平方数
- 根据上述等式，解出$p$和$q$。

### p-1光滑
**光滑数（Smooth number）**：可以分解为小素数乘积的正整数

使用`Pollard's p-1`算法：
```python
from gmpy2 import * 
a = 2 
n = 2 
while True: 
	a = powmod(a, n, N) 
	res = gcd(a-1, N) 
	if res != 1 and res != N: 
		q = n // res 
		d = invert(e, (res-1)*(q-1)) 
		m = powmod(c, d, N) 
		print(m) 
		break 
	n += 1
```

### p+1光滑
使用`Williams's p+1`算法

```python
def mlucas(v, a, n): 
""" Helper function for williams_pp1(). Multiplies along a Lucas sequence modulo n. """ 
	v1, v2 = v, (v**2 - 2) % n 
	for bit in bin(a)[3:]: v1, v2 = ((v1**2 - 2) % n, (v1*v2 - v) % n) if bit == "0" else ((v1*v2 - v) % n, (v2**2 - 2) % n) 
	return v1 

for v in count(1): 
	for p in primegen(): 
		e = ilog(isqrt(n), p) 
		if e == 0: break 
		for _ in xrange(e): v = mlucas(v, p, n) 
		g = gcd(v-2, n) 
		if 1 < g < n: return g # g|n 
		if g == n: break
```

### 模不互素
**攻击原理：** 当存在两个公钥的$N$不互素时，我们显然可以直接对这两个数求最大公因数，然后直接获得$p$和$q$，进而获得相应的私钥。

### 共模攻击
**攻击条件：** 当两个用户使用相同的模数$N$、不同的私钥时，加密同一明文消息时即存在共模攻击。

**攻击原理：** 
设两个用户的公钥分别为$e_1$和$e_2$，且互质，明文消息为$m$，则密文为
$$\begin{align} 
c_1=m^{e_1} \ mod \ N \\ 
c_2=m^{e_2} \ mod \ N
\end{align}$$
当攻击者截获$c_1$和$c_2$后，用拓展欧几里得算法求出满足 $re_1+se_2=1 \ mod \ N$ 的两个整数$r$和$s$，由此可得
$$\begin{align}
c_1^rc_2^s \equiv& \ m^{re_1}m^{se_2} \ mod \ N \\
\equiv& \ m^{re_1+se_2} \ mod \ N \\
\equiv& \ m \ mod \ N
\end{align}$$

## 3 攻击——公钥指数
### 小公钥指数攻击
**攻击条件：** $e$特别小，比如$e=3$

**攻击原理：** 
假设用户使用的秘钥$e=3$。由于加密关系为
$$c \equiv m^3 \ mod \ N$$
则有
$$\begin{align}
m^3 =& c + kN \\
m =& \sqrt[3]{c+kN}
\end{align}$$
攻击者可以从小到大枚举$k$，依次开三次根，直到开出整数为止。

### RSA衍生算法——Rabin算法
**攻击条件：** Rabin算法的特征在于$e=2$

## 4 攻击——私钥d
### 私钥泄露
私钥泄露后，自然可以解密密文，甚至可以对模数$N$进行分解。

**工具：**
- RsaConverter.exe ([https://sourceforge.net/projects/rsaconverter/](https://sourceforge.net/projects/rsaconverter/) , for windows )
- [rsatool.py](https://github.com/ius/rsatool/blob/master/rsatool.py)

### Wiener's Attack
**攻击条件：** $d<\frac{1}{3}N^{\frac{1}{4}}$

**攻击原理：**
- [https://en.wikipedia.org/wiki/Wiener%27s_attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)
- [https://sagi.io/2016/04/crypto-classics-wieners-rsa-attack/](https://sagi.io/2016/04/crypto-classics-wieners-rsa-attack/)

**工具：**
- [https://github.com/pablocelayes/rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack)
- [https://github.com/orisano/owiener](https://github.com/orisano/owiener)

### Extending Wiener's Attack
- [《Extending Wiener's Attack in the Presence of Many Decrypting Exponents》](https://www.sci-hub.ren/https://link.springer.com/chapter/10.1007/3-540-46701-7_14)
- [https://ctf-wiki.org/crypto/asymmetric/rsa/d_attacks/rsa_extending_wiener/](https://ctf-wiki.org/crypto/asymmetric/rsa/d_attacks/rsa_extending_wiener/)