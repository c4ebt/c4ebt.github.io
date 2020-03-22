---
layout: single
title:  "CuarenTeFa Apruebo Writeup"
---

# CuarenTeFa "Apruebo" Writeup
Acá dejo mi writeup para el challenge "Apruebo" hecho por [dplastico](https://dplastico.me/) para el CTF CuarenTeFa del 21 de Marzo de 2020 organizado por [L4tinHTB](https://t.me/joinchat/GgG8nxC3jHVwxNFeyQt_OA).

El desafío pertenecía a la categoría PWN y tenia un valor de 300 puntos (subanle el puntaje a PWN), y fue resuelto solamente por dos participantes.
Al día siguiente del CTF los organizadores hicieron un live resolviendo todos los challenges, pero la solución aun no esta publicada en youtube al momento en que escribo este writeup :/ .

### Apruebo
Como en la mayoría de desafíos PWN, comenzamos con un archivo zip y una IP y puerto a los que nos podemos conectar. El objetivo en este challenge va a ser explotar un Buffer Overflow en el binario que se nos da para poder conseguir una shell en la maquina remota y así poder leer la flag.
[Aqui](https://c4ebt.github.io) tienen un link donde pueden descargar el archivo, y pueden emular la situación del binario corriendo en una maquina remota ustedes mismos haciendo ```nc -nvlp 5555 -e apruebo``` y tendrán el servicio corriendo en ```127.0.0.1:5555```.

![](http://c4ebt.github.io/assets/images/Inicio.png)

Descomprimimos el zip, cambiamos los archivos a modo ejecutable y estamos listos para empezar.
Vemos que tenemos un binario y una libc, asumimos que es la libc de la maquina remota que nos es entregada para poder conseguir direcciones y demás. Al correr el binario, este espera nuestro input y luego printea ```Q4{CTF2020}!```, una referencia troll por parte del creador del desafío a una flag del estilo Q4{} usadas en un CTF pasado.
