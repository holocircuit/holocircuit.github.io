---
layout: post
title:  "\"Unofficial\" - 35C3 CTF (Part 1 - Linear Equations)"
date:   2019-01-06 00:00:00 +0000
author: holocircuit
tags:   ctf cryptography
---

In this series of posts, we'll go through how to solve [Unofficial](https://ctftime.org/task/7416), a cryptography challenge from 35C3 CTF. 

The first couple of posts are just going to be a bit of background about linear algebra - go [to Post 3][post3] if you just want the challenge solution.


## Simultaeneous (linear) equations
The first thing we need to know for this challenge is how to solve simultaeneous equations. We'll use the convention that $$x_1, ..., x_n$$ are our unknown variables. Here's an example:

$$
\begin{align} 
x_1+x_2 &= 1 \\ 
2x_1+3x_2 &=5 
\end{align}
$$

Solving this is pretty easy! Maybe you did something like this in high school. We can subtract twice the first equation from the second, to get
$$
x_2 = 3
$$
and then from there we have a value for $$x_2$$, and then we can substitute that back in to get a value for $$x_1$$.

In general, a set of $$m$$ linear equations in $$n$$ unknowns looks like the following:

$$
\begin{align}
a_{11}x_1 + ... + a_{1n}x_n &= b_1 \\
a_{21}x_1 + ... + a_{2n}x_n &= b_2\\
...\\
a_{m1}x_1 + ... + a_{mn}x_n &= b_m
\end{align}
$$

(where the $$a$$ and $$b$$ values are some numbers). Our goal is going to be to write an algorithm to find all possible values for the $$x_i$$ that give solutions.

Mathematicans love matrices, so they'll often write this down as something that looks like

$$\begin{bmatrix}
a_{11} & ... & a_{1n} & b_1\\
a_{21} & ... & a_{2n} & b_2\\
& ... &\\
a_{m1} & ... & a_{mn} & b_m\\
\end{bmatrix}
$$

where the last column are the numbers on the right-hand-side of our equation, and the rest are the coefficients.

## Gaussian elimination
[Gaussian elimination](https://en.wikipedia.org/wiki/Gaussian_elimination) is a general method for solving these equations. It's basically not much more complicated than the high-school example above!
The general idea is we have 3 simple "steps" we can perform to simplify our set of equations, which don't affect the set of solutions. We're then going to use those to change the set of equations to a simple form, where we can easily solve them.

I'll label our equations $$E_1, ..., E_n$$.

### The 3 steps
#### Adding a multiple of another row
In the example above, we changed one of our equations by adding a multiple of another. To be specific, we changed the second equation by subtracting twice the first equation. We can write this down as:

$$
E_2 \rightarrow E_2 + (-2)E_1
$$

This doesn't change the set of solutions: any $$x_1, ..., x_n$$ that solve the original equations solve this one too, as all the equations here are linear. And this step is reversible, so we can't have added any new equations.

We can write this more generally by picking any two equations, and any constant, and doing the replacement

$$
E_j \rightarrow E_i + KE_j \tag{1}
$$

In matrix form: "Add $$K$$ times row $$i$$ to row $$j$$".


#### Multiplying an equation by a non-zero number
If we have an equation, then we can multiply it by some (non-zero) number to get another equation. This doesn't change the set of solutions - as long as we're multiplying by a non-zero number, we can "get back" to our original equation by just multiplying the inverse. This looks like

$$
E_i \rightarrow KE_i \tag{2}
$$

In matrix form: "Multiply row $$i$$ by $$K$$."

#### Swapping two equations
We can also swap two equations - which shouldn't change the solutions, because we've just changed the order we're writing them down!

$$
E_i, E_j \rightarrow E_j, E_i \tag{3}
$$

In matrix form: "Swap two rows".

### Upper triangular form
We know the steps - what are we aiming for?
We're going to try and rearrange our equations so the "bottom-left" of our coefficients are all 0 - i.e. so it looks like

$$\begin{bmatrix}
* & * & * & ... & * & b_1\\
0 & * & * & ... & * & b_2\\
0 & 0 & * & ... & * & b_3\\
& ... &\\
0 & 0 & * & ... & * & b_n\\
\end{bmatrix}
$$

(Formally this is sometimes called *upper triangular* form.)






## Working over mod p
In cryptography, we often don't work with integers like we did above. Instead, we work _mod p_. This means that we add 



[post3]: www.google.com
