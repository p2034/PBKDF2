<h1>PBKDF2</h1>

PBKDF2 (Password-Based Key Derivation Function 1) is key derivation functions with a sliding computational cost, used to reduce vulnerabilities of brute-force attacks.[wiki](https://en.wikipedia.org/wiki/PBKDF2)

<h2>Usage:</h2>
There is two versions of pbkdf2: oop (class PBKDF2) and functional (one function), copy one of them in your project.

You can see how to use this in /tests/ folder

Can be used with [SHA256](https://github.com/p2034/SHA256) (../SHA256) and [HMAC](https://github.com/p2034/HMAC) (../HMAC)

<h2>Compile:</h2>

1. Go to tmp
2. Run:

```bash
cmake ./
make
```

3. And now you have test.out file in tmp
