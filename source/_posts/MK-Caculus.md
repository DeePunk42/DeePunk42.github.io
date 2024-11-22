---
title: MK_Caculus
date: 2023-05-10 10:22:14
tags:
- caculus
categories:
- 数理笔记
mathjax: true
---

# 函数基础

## 双曲函数

$$ 双曲正弦函数\space y=sh \space x =\frac{e^x-e^{-x}}{2} $$

$$ 双曲余弦函数\space y=ch \space x =\frac{e^x+e^{-x}}{2} $$

$$ 双曲正切函数\space y=th \space x=\frac{sh\space x}{ch\space x} =\frac{e^x-e^{-x}}{e^x+e^{-x}} $$

## 三角函数

$$ secA=\frac{1}{cosA} $$

$$ cscA=\frac{1}{sinA} $$

------

# 极限

## 数列极限

$$ \forall \varepsilon>0,\exists N>0,s.t.|x_n-A|<\varepsilon,when\space n>N $$

## 自变量趋于无穷大时函数极限

$$ \forall \varepsilon >0,\exist X>0,s.t.|f(x)-A|<\varepsilon,when \  \ x>X/x<X/|x|>X $$

## 自变量趋近有限值时函数极限

$$ \forall \varepsilon>0,\exist \delta>0,s.t.|f(x)-A|<\varepsilon,when \ \ 0<|x-x_0|<\delta $$

## 单侧极限：dddd

## 数列极限与函数极限的关系

### 定理

$$ 设f(x)在x_0某个去心领域\mathring{U}(x_0)内有定义，则\ \ \lim_{n \to \infty}f(x)=A \Longleftrightarrow \forall \{x_n\}满足(1)\ \ x_n\in \mathring{U}(x_0);(2)\ \ \lim_{x\to\infty}x_n=x_0,\ \ \lim_{n \to \infty}f(x_n)=A $$

### 用法

证明函数极限不存在

1. 找收敛于$x_0$的数列$\{x_n\}$，但$f(x_n)$极限不存在
2. 找两个收敛于的数列，但函数极限不同

## 夹逼准则

## 单调有界准则

------

# 无穷

## 无穷小

$$ \forall\varepsilon>0,\exist \delta>0,s.t.|f(x)|<\varepsilon ,when \ \ 0<|x-x_0|<\delta $$

## 无穷大

$$ \forall M>0,\exist \delta>0,s.t.|f(x)|>M,when \ \ 0<|x-x_0|<\delta $$

## 定理

无穷小与有界变量之积为无穷小

## 重要极限

$$ \lim_{x\to\infty}(1+\frac{1}{x})^x=e $$

## 等价无穷小

------

# 一元函数积分学

## 函数可积的充分条件

$$ f(x)在[a,b]上连续 \Longrightarrow f(x)在[a,b]上可积\Longleftarrow f(x)在[a,b]上有界，且只有有限个第一类间断点 $$

## 定理

### 估值定理

$$ M,m是f(x)区间[a,b]上最大值和最小值，则 $$

$$ m(b-a)\leq \int^b_af(x)dx\leq M(b-a),(a<b) $$

### 积分中值定理

$$ 设f(x)\in C[a,b],则至少存在一点\xi \in(a,b)，使得 $$

$$ \int^b_af(x)dx=f(\xi)(b-a) $$

## 积分上限函数

### 定义

$$ \Phi(x)=\int^x_af(t)dt\ \ \ \ (a\leq x\leq b) $$

### 定理

$$ f(x)\in C[a,b],则\Phi'(x)=f(x) $$

$$ f(x)\in C[a,b]，则f(x)在[a,b]上必有原函数 $$

## 微积分基本定理

## 不定积分

## 反常积分

### 无穷区间

### 无界

## 几何应用

### 极坐标下求面积

扇形面积微元：

$$ dA=\frac{1}{2}r^2(\theta)d\theta $$

------

# 一元函数微分学

## 导数

$$ 函数在某点可导\implies 函数在某点连续 $$

$$ 函数在某点可导\nLeftarrow 函数在某点连续 $$

### 反函数求导

$$ (f^{-1})'(x)=\frac{1}{f'(y)} $$

### 参数式函数、反函数二阶求导



## 隐函数求导

### 对数求导法

## 参数式函数求导

## 高阶导数

$$ (sinx)^{(n)}=sin(x+\frac{\pi}{2}n) $$

$$ (cosx)^{(n)}=cos(x+\frac{\pi}{2}n) $$

$$ [\alpha u(x)+\beta v(x)]^{(n)}=\alpha u^{(n) }(x)+\beta v^{(n)}(x) $$

莱布尼兹公式：

$$ (uv)^{(n)}=\sum^{n}_{k=0}C^k_nu^{(n-k)}v^{(k)} $$

## 微分

$$ \Delta y=A\Delta x+o(\Delta x) $$

$$ 可导\iff 可微 $$

$$ \frac{dy}{dx}=f'(x) $$

### 线性近似

$$ f(x) \approx f(x_0)+f'(x_0)(x-x_0) $$

## 微分中值定理



### 罗尔中值定理

### 拉格朗日中值定理

### 柯西中值定理

## 泰勒公式



## 曲率

### 弧微分公式

$$ ds=\sqrt{1+y'^{2}}dx $$

## 曲率

$$ K=\lim_{\Delta s\to 0}|\frac{\Delta \alpha }{\Delta s}|=|\frac{d\alpha }{ds}| $$

### 曲率计算公式

懒得写了

------

# 一元函数积分学

## 公式

$$
 \int \sec^2x\mathrm{d}x=\tan x+C \\\\ 
 \int \csc^2x\mathrm{d}x=-\cot x+C \\\\ 
 \int \sec x\tan x \mathrm{d}x =\sec x+C \\\\  
 \int \csc x\cot x\mathrm{d}x=-\csc x+C \\\\ 
 \int \frac{1}{\sqrt{1-x^2}}\mathrm{d}x=\arcsin x+C \\\\ 
 \int \frac{1}{1+x^2}\mathrm{d}x=\arctan x+C \\\\ 
$$

$$
\int \tan x\mathrm{d}x=-\ln\lvert \cos x\rvert +C\\\\
 \int \cot x\mathrm{d}x=\ln\lvert\sin x\rvert +C\\\\
 \int \sec x\mathrm{d}x=	\ln \lvert \sec x+\tan x\rvert +C\\\\
 \int \csc x\mathrm{d}x=\ln\lvert \csc x- \cot x\rvert +C\\\\
 \int \frac{1}{a^2-x^2}\mathrm{d}x=\frac{1}{2a}\ln\lvert\frac{a+x}{a-x}\rvert +C\\\\
 \int \frac{1}{\sqrt{x^2\pm a^2}}\mathrm{d}x=\ln\lvert x+ \sqrt{x^2\pm a^2}\rvert +C\\\\\\\\
$$


$$
\int ^{\frac{\pi}{2}}_0f(\sin x)\mathrm{d}x=\int ^{\frac{\pi}{2}}_0f(\cos x)\mathrm{d}x\\\\
 \int ^{\pi}_0xf(\sin x)\mathrm{d}x=\frac{\pi}{2}\int ^{\pi}_0f(\sin x)\mathrm{d}x\\\\
 \int ^{\pi}_0f(\sin x)\mathrm{d}x=2\int ^{\frac{\pi}{2}}_0f(\sin x)\mathrm{d}x
$$

# 常微分方程

常微分方程：未知函数一元

偏微分方程：未知函数二元及以上

## 一阶微分方程(First-Order Differential Equations)

### 齐次方程

$$
 \frac{dy}{dx}=\varphi (\frac{y}{x}) 
$$



$$ 令u=\frac{y}{x},\space u+x\frac{du}{dx}=\varphi(u) $$

### 一阶线性方程

$$
\frac{dy}{dx}+P(x)y=Q(x)\\\\
 y=\frac{1}{v(x)} \int v(x)Q(x)dx,\space v=e^{\int P(x)dx}
$$

### 伯努利(Bernoulli)方程

$$
\frac{dy}{dx}+P(x)y=Q(x)y^n ,\space(n \neq 0,1)\\\\
 y^{-n}\frac{dy}{dx}+P(x)y^{1-n}=Q(x)
$$

$$ 令z=y^{1-n},\space \frac {dz}{dx}=(1-n)y^{-n} \frac{dy}{dx} $$

$$ 将y代回原方程,\space \frac{dz}{dx}+(1-n)P(x)z=(1-n)Q(x) $$

## 可降价的高阶微分方程

1. $y^{(n)}=f(x)$

2. $y''=f(x,y')$

3. $y''=f(y,y')$

   令$p=y'$

## 二阶齐次线性方程

$$
\frac{d^2y}{dx^2}+P(x)\frac{dy}{dx}+Q(x)y=0
$$

### 线性微分算子

$$
L(C_1 y_1+C_2y_2)=C_1L(y_1)+C_2L(y_2)
$$

定理1：二阶齐次线性方程的两个解的线性组合仍是该方程的解

定理2：设$y_1(x),y_2(x)$均不为零，则线性相关$\Leftrightarrow $两函数之比恒等于一个常熟，反之不恒等

定理3： 两个线性无关特解的线性组合为通解

### 二阶常系数齐次线性方程

$$
 y''+py'+qy=0 
$$

$$ 欧拉待定指数函数法：设方程有解y=e^{rx},代入得:r^2+pr+q=0（特征方程） $$

1. $\Delta>0$
2. $\Delta=0$

$$ 需找出另一解，设\frac{y_2}{y_1}=u(x)不为常数 $$

$$ y_2=e^{r_1x}u(x)，求导两次 $$

$$ 代入微分方程，整理,一通操作：y_2=xe^{r_1x} $$

1. $\Delta<0$

$$
r=\alpha \pm i\beta\\\\
 y=e^{\alpha x}(C_1\cos\beta x+C_2\sin \beta x)
$$





### 二阶非齐次线性方程

# 多元函数积分学

## 数量值函数

### 二重

### 三重

### 第一类曲线

### 第一类曲面

### 质心

## 向量值函数

### 第二类曲线

### 第二类曲面

### 公式

#### 格林公式

**第二类曲线积分**与**二重积分**
$$
\iint\limits_D\bigg(\frac{\part{Q}}{\part{x}}-\frac{\part{P}}{\part{y}}\bigg)dxdy=\oint_LPdx+Qdy
$$

$$
\iint\limits_D\bigg(\frac{\part{Q}}{\part{x}}-\frac{\part{P}}{\part{y}}\bigg)dxdy=\oint_{L_1}Pdx+Qdy+\oint_{L_2}Pdx+Qdy
$$

#### 高斯公式

**第二类曲面积分**与**三重积分**
$$
\iiint\limits_V\bigg(\frac{\part{P}}{\part{x}}+\frac{\part{Q}}{\part{y}}+\frac{\part{R}}{\part{z}}\bigg)dV=\oiint\limits_SPdydz+Qdzdx+Rdxdy
$$

#### 斯托克斯公式

**空间第二类曲线积分**与**第二类曲面积分**
$$
\oint\limits_LPdx+Qdy+Rdz=\iint\limits_S\left |\begin{array}{cccc}
dydz &dzdx  &dxdy \\
\frac{\part}{\part{x}} &\frac{\part}{\part{y}}&\frac{\part}{\part{z}}  \\
P & Q &R \\
\end{array}\right|
$$


### 路径无关

# 无穷级数

## 常用级数

几何级数：
$$
\sum_{n=0}^{\infty}aq^n=\left\{
\begin{aligned}
\frac{a}{1-q} & , & |q|<1, \\
发散 & , & |q|>1
\end{aligned}
\right.
$$
调和级数

P级数
$$
\sum_{n=1}^{\infty}(-1)^n\frac{1}{n^p}=\left\{
\begin{aligned}
发散 & , & p\leq 0, \\
条件收敛 & , & 0<p\leq 1, \\
绝对收敛 & , & p>1
\end{aligned}
\right.
$$


## 常数项级数判别

### 正数项

#### 比较判敛法

n>N,k

比值为正数

#### 比值判敛法

达朗贝尔

#### 根值判敛法

柯西

### 交错项

#### 莱布尼兹

