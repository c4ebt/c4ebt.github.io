---
layout: single
title:  "CuarenTeFa Apruebo Writeup"
---
Acá dejo mi writeup para el challenge "Apruebo" hecho por [dplastico](https://dplastico.me/) para el CTF CuarenTeFa del 21 de Marzo de 2020 organizado por [L4tinHTB](https://t.me/joinchat/GgG8nxC3jHVwxNFeyQt_OA). El desafío pertenecía a la categoría PWN y tenia un valor de 300 puntos (subanle el puntaje a PWN), y fue resuelto solamente por dos participantes. En este writeup voy a explicar detalladamente todos los procesos por los que se tiene que pasar para lograr un exploit exitoso, introduciendo los memory leaks y como este funciona relacionado a la PLT y GOT.

Al día siguiente del CTF los organizadores hicieron un live resolviendo todos los challenges, pero la solución aun no esta publicada en youtube al momento en que escribo este writeup. Los métodos usados en su solución y en la mía son prácticamente los mismos, dplastico implementó herramientas automáticas y yo aquí voy a hacerlo todo manual y explicado paso a paso para que se entienda :D.

## Apruebo
Como en la mayoría de desafíos PWN, comenzamos con un archivo zip y una IP y puerto a los que nos podemos conectar. El objetivo en este challenge va a ser explotar un Buffer Overflow en el binario que se nos da para poder conseguir una shell en la maquina remota y así poder leer la flag.
[Aqui](https://c4ebt.github.io) tienen un link donde pueden descargar el archivo, y pueden emular la situación del binario corriendo en una maquina remota ustedes mismos haciendo ```nc -nvlp 5555 -e apruebo``` y tendrán el servicio corriendo en ```127.0.0.1:5555```.

![](http://c4ebt.github.io/assets/images/Inicio.png)
Descomprimimos el zip, cambiamos los archivos a modo ejecutable y estamos listos para empezar.
Vemos que tenemos un binario y una libc, asumimos que es la libc de la maquina remota que nos es entregada para poder conseguir direcciones y demás. Al correr el binario, este espera nuestro input y luego printea `Q4{CTF2020}!`, una distracción por parte del creador del desafío a una flag del estilo Q4{} usadas en un CTF pasado.
Hacemos el comando `file` con el archivo para ver si se trata de un binario de 32 o 64 bits:

![](http://c4ebt.github.io/assets/images/checksec.png)

y luego hacemos `checksec` para identificar las protecciones que tiene:

![](http://c4ebt.github.io/assets/images/checksec.png)

Vemos que la única protección que tiene el binario es `NX`, por lo que no podremos ejecutar un simple buffer overflow con shellcode ya que el stack no es ejecutable. Tendremos que optar entonces por una ROP Chain para poder obtener una shell.
Comenzamos reverseando brevemente el binario para hacernos una idea de lo que hace. Para esto vamos a usar radare2:

![](http://c4ebt.github.io/assets/images/radare-beginning.png)

Vemos 2 funciones que nos podrían interesar por ahora: `main` y `vuln`.
`Main`:

![](http://c4ebt.github.io/assets/images/radare-main.png)

Tomando una mirada mas cercana a `main` nos damos cuenta de que lo único que hace es llamar a `vuln` y luego printear algo al stdout mediante la función `write`, que podemos asumir seguramente es el `Q4{CTF2020}!` que vimos al ejecutar el binario. 

Pasamos a mirar la función `vuln`. Esta nos interesa mas:

![](http://c4ebt.github.io/assets/images/radare-main.png)

Vemos una llamada a la función `read`, que es la función que nos pide el input inicialmente al correr el binario. Es esta función la que vamos a usar para empezar nuestro exploit, es decir, la que vamos a overflowear.

Suficiente reversing, pasamos a ver como crashear el binario y a construir nuestro exploit. Abrimos el binario en gdb (con el plugin peda):

![](http://c4ebt.github.io/assets/images/pattern-create.png)

Creamos una string de 200 caracteres con patron identificable para luego poder saber donde tenemos el offset para sobreescribir el EIP

![](http://c4ebt.github.io/assets/images/pattern-offset.png)

Podemos comprobar esto en la terminal con python:

![](http://c4ebt.github.io/assets/images/pythoncrash.png)

Efectivamente crasheamos el programa, usando el comando `dmesg` podemos analizar por que ocurrió el crash:
```
[ 6185.322908] apruebo[11718]: segfault at 41414141 ip 0000000041414141 sp 00000000ff974fb0 error 14 in libc-2.29.so[f7d7e000+1d000]
[ 6185.322915] Code: Bad RIP value.
```
Vemos que 4 bytes sobreescribieron el EIP, causando el crash. Estos 4 bytes son los que introdujimos con el comando de python, ya que printeamos 144 en vez de 140 para lograr el crash.

Con esta información empezamos a construir nuestro exploit.
Para este challenge vamos a usar `pwntools`, una librería para exploiting en python muy util.
Nuestro exploit va quedando así:

```python
#!/usr/bin/python
from pwn import *

p = process("./apruebo")
#p = gdb.debug("./apruebo")

junk = "A"*140

payload = junk

p.sendline(payload)
```

Nuestro objetivo va a ser sobreescribir el eip para poder ejecutar la función que queramos. En este caso vamos a llamar a `write` con algunos argumentos especiales para leakear la dirección base de libc en la memoria, que no es fija debido a que el sistema tiene ASLR (Address Space Layout Randomization). Desde ahi, teniendo la direccion base de libc, vamos a poder llamar a `system` con `/bin/sh` para conseguir una shell y completar el challenge.

Entonces ahora tenemos que conseguir algunas direcciones para poder ejecutar nuestro exploit. Nuestra payload, por ahora, necesita lo siguiente:

- `140 bytes de padding para sobreescribir el EIP` - Conseguido
- Dirección de la función `write` para ejecutar el memory leak,
- Direcciones para los parámetros de la función `write`, necesarios para el memory leak también.

#### Memory leak
Para llevar a cabo un memory leak de la dirección de libc necesitamos entender primero los conceptos de PLT y GOT. Creo que [este video de LiveOverflow](https://youtu.be/kUk5pw4w0h4) hace un muy buen trabajo explicándolos, pero esta en inglés así que voy a hacer lo mejor que pueda para explicarlos en este writeup.
Reverseando el binario vimos que las funciones `write` y `read` eran llamadas en determinados puntos de la ejecución. Pero a diferencia de las funciones `main` y `vuln`, que están "dentro" del binario, `write` y `read` son funciones externas importadas desde la libc.
Esto es implementado en la mayoría de binarios desde hace muchísimo tiempo, ya que ahorra mucho trabajo, espacio y velocidad. Entonces, como se llama a estas funciones si no están dentro del binario? Volvemos un poco a radare2 para analizarlo. 

![](http://c4ebt.github.io/assets/images/radare-functions.png)

Vemos que las funciones `write` y `read` son simplemente instrucciones `jpm` a otra dirección. Si las analizamos en conjunto, corriendo el comando `V @ sym.imp.read` y subiendo  un poco, nos podemos dar cuenta de que ambas son simplemente entradas de la PLT, o Procedure Linkage Table.

![](http://c4ebt.github.io/assets/images/radare-plt.png)

