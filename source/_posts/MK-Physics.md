---
title: MK_Physics
date: 2023-05-09 16:05:49
tags:
- Physics
categories:
- 数理笔记
mathjax: true
---


# 振动&波

## 简谐振动

### 简谐振动的速度、加速度

$$
x=Acos(\omega t+\varphi)\\\\
 v=-\omega A sin(\omega t+\varphi)\\\\
 a=-\omega ^2 A cos(\omega t+\varphi)\\\\
 运动学特性:a=-\omega ^2 x\\\\
 动力学特性:F=ma=-m\omega ^2x=-kx\\\\
 等效劲度系数:k=m\omega^2
$$

### 简谐振动的能量

#### 公式

$$
(瞬时)振动势能:E_p=\frac{1}{2}kx^2=\frac{1}{2}kA^2cos^2(\omega t+\varphi)\\\\
 (瞬时)振动动能:E_k=\frac{1}{2}mv^2=\frac{1}{2}m\omega^2 A^2 sin^2(\omega t+\varphi)\\\\
 E=E_p+E_k=\frac{1}{2}kA^2\\\\
 平均能量:\overline{E}_p=\overline{E}_k=\frac{1}{4}kA^2
$$

p.s.振动势能和弹性势能一般**不相同**

#### 证明简谐运动

由于对下式求导： 
$$
E=E_p+E_k=C
$$
可得：
$$
w^2=\frac{k}{m}
$$


故可先写出振动体系能量关系，若能量守恒，就可求导得出谐振子动力学方程，多用于非机械振动

### 简谐振动的运动学描述

#### 解析法
$$
w=\sqrt{\frac{k}{m}}\\
 A=\sqrt{x^2+\frac{v^2}{w^2}}\\
 tg\varphi=-\frac{v_0}{wx_0}
$$

#### 旋转矢量法

#### 曲线法

### 简谐振动的合成

#### 同频率平行

$$
x_1=A_1cos(\omega t+\varphi_1)\\\\
 x_2=A_2cos(\omega t+\varphi_2)\\\\
 x=x_1+x_2=x_1=Acos(\omega t+\varphi)\\
$$

由**旋转矢量法**求得：


$$
A= \sqrt{A_1^2+A_2^2+2A_1A_2\cos(\varphi_2-\varphi_1)}\\\\
 tg\varphi=\frac{A_1\sin\varphi_1+A_2\sin \varphi_2}{A_1\cos\varphi_1+A_2\cos\varphi_2}\\
$$

#### 不同频率平行

$$
x_1=A\cos(\omega_1 t+\varphi)\\\\
 x_2=A\cos(\omega_2 t+\varphi)\\\\
 x=x_1+x_2=2A\cos\frac{\omega_2-\omega_1}{2}t\cos(\frac{\omega_1+\omega_2}{2}t+\varphi)
$$

当$$ \omega_1 $$和$$ \omega_2 $$都较大且相差很小时，$$ \cos\frac{\omega_2-\omega_1}{2}t $$ 的周期比$$ cos(\frac{\omega_1+\omega_2}{2}t+\varphi) $$ 长得多，前者频率为**调制频率**，后者频率为**载频**

#### 垂直

##### 同频率

$$
x=A_1\cos(\omega t+\varphi_1)\\\\
 y=A_2\cos(\omega t+\varphi_2)\\\\
 \frac{x^2}{A_1^2}+\frac{y^2}{A_2^2}-2\frac{x}{A_1}\frac{y}{A_2}\cos(\varphi_2-\varphi_1)=\sin^2(\varphi_2-\varphi_1)
$$

1. 一般为椭圆，形状由$$ \Delta \varphi $$决定
2. $$ \Delta \varphi=2k\pi $$时，为直线，合振动**为简谐振动**
3. $$ \Delta \varphi=\pm\frac{\pi}{2} $$时，为椭圆，合振动**不为简谐振动**，正为顺时针

##### 不同频率

若频率有简单倍数关系，形成**李萨如图形**

## 波

### 描述量

**波速**（相速）：
$$
u=\sqrt{\frac{B}{\rho}},\ \ B为弹性模量\ \rho为质量密度（惯性）
$$
机械波波速取决于**介质本身的性质**，与波源振动的频率无关

### 波动方程
$$
y=A\cos[\omega(t\mp \frac{x}{u})+\varphi_0]
$$

### 动力学方程

将运动学方程中$y$对$t$，$x$求二阶偏导
$$
\frac{\partial^2{y}}{\partial{x}^2}=\frac{1}{u}\frac{\partial^2y}{\partial{t}^2}
$$

### 波的能流和强度

#### 波的能量


$$
质元动能:\mathrm{d}E_k=\frac{1}{2}(\rho\mathrm{d}V)\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]\\\\
 质元弹性势能:\mathrm{d}E_p=\frac{1}{2}(\rho\mathrm{d}V)\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]\\\\
 质元能量:\mathrm{d}E=(\rho\mathrm{d}V)\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]\\\\
 能量密度:w(x)=\frac{\mathrm{d}E}{\mathrm{d}V}=\rho\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]\\\\
 平均能量密度:\overline{w}(x)=\frac{1}{T}\int ^T _0\rho\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]\mathrm{d}t=\frac{1}{2}\rho\omega^2A^2
$$
质元的机械能不是常量，随时间周期性变化，但能量密度在一个周期内平均值是常量

#### 波的能流和能流密度
$$
能流:P=wuS=\frac{\mathrm{d}E}{\mathrm{d}V}=\rho\omega^2A^2\sin^2[\omega(t-\frac{x}{u})]uS\\\\
 平均能流:\overline{P}=\overline{w}uS=\frac{1}{2}\rho\omega^2A^2uS\\\\
 平均能流密度(波强):I=\frac{\overline{P}}{S}=\frac{1}{2}\rho\omega^2A^2u
$$



### 波的叠加和干涉


$$
\Delta\varphi=\varphi_2-\varphi_1-\frac{2\pi}{\lambda}(r_2-r_1)
$$
为$ 2k\pi $时加强，$ (2k+1)\pi $时减弱

### 驻波

#### 半波损失

