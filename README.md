<h1>TRABAJO FINAL REDES Y SEGURIDAD INFORMATICA</h1>

<h2>INTREGRANTES</h2>
<li>Nicolas Maximiliano Barrientos</li>
<li>Maximiliano Ariel Fava</li>

<h2>INTRODUCCION</h2>
<p>El presente informe detalla el proceso del desarrollo en lenguaje de programación C sobre la plataforma Unix/Linux de un analizador en tiempo real que muestre la distribución estadística de los protocolos más destacables del tráfico de la red (Ethernet, ARP, IP, UDP, TCP).</p>

<h2>ENTORNO DE TRABAJO</h2>
<p>Para realizar este trabajo práctico final, la primera decisión fue usar la IDE Visual Studio Code como entorno de desarrollo, apoyándonos en una de las extensiones que nos brinda esta IDE llamada GitHub Copilot la cual está basada en la tecnología de OpenAI, y utilizando control de versiones GIT para subir el proyecto al sitio web www.Github.com que nos facilitó el trabajo remoto en conjunto.</p>

<h2>DECISIONES DE PROGRAMACION</h2>
<p>Cada uno de nosotros comenzó escribiendo un código por separado. Luego, unificamos ambos trabajos en uno solo, lo que nos permitió corregir errores y aprovechar lo mejor de ambos códigos para formar un único código sólido.</p>
<p>Obtenemos un listado de todos los dispositivos de red disponibles, el usuario selecciona el dispositivo de red de su preferencia y se validará. Las validaciones son: si hubo un error al abrir la interfaz, si hubo un warning y que la interfaz sea de tipo Ethernet. Una vez finalizadas las validaciones, imprimimos por pantalla el nombre del dispositivo, su Dirección de Red y su Máscara de Subred.</p>
<p>Utilizando un ciclo while() realizamos el bucle para poder capturar e imprimir por pantalla continuamente en tiempo real la cantidad de paquetes solicitados o de forma indefinida hasta que el programa termine o el usuario con Ctrl + C lo interrumpa de forma manual.</p>
<p>Para diferenciar que tipo de protocolo se encuentra encapsulado en cada datagrama IP capturado utilizamos un puntero a la cabecera Ethernet. Cada vez que capturamos un datagrama IP analizamos qué tipo de protocolo tenía encapsulado e imprimimos su cabecera por pantalla.</p>
<p>Al finalizar el programa se imprimen las estadísticas finales de los paquetes capturados durante la ejecución independientemente si se interrumpe su ejecución con el comando Ctrl + C o al finalizar la cantidad de capturas solicitadas por el usuario.</p>

<h2>DIFICULTADES Y PROBLEMATICAS</h2>
<p>Una de las principales problemáticas que se nos presentó a la hora de realizar el trabajo práctico fue en el momento de implementar el primer punto de mostrar por pantalla en tiempo real con un thread separado dedicado a ello, debatimos el hecho de cómo podría ser la mejor forma de mostrarlo e implementarlo, empezamos primero por implementar el hilo dedicado a ello. </p>
<p>Luego se nos presentó el problema de que a la hora de implementar la captura en tiempo real, no se mostraba como queríamos sino después de un delay de unos segundos, investigamos y descubrimos que estábamos declarando e iniciando la función signal despues de la declaracion e inicializacion de hilos lo que llevaba a un conflicto entre ambos. La razón principal es que las señales y el manejo de señales son, por defecto, propiedades del proceso, y la configuración de un manejador de señales puede afectar a todos los hilos en ese proceso.</P>

