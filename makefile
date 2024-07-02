# Definir el compilador
CC = gcc

# Opciones de compilación, -g para depuración, -Wall para mostrar advertencias, y -O2 para optimización
CFLAGS = -g -Wall -O2

# Bibliotecas a enlazar, por ejemplo, libpcap para captura de paquetes
LIBS = -lpcap

# Nombre del ejecutable a generar
TARGET = tp3

# Archivos fuente
SOURCES = tp3.c

# Objetos (archivos objeto)
OBJECTS = $(SOURCES:.c=.o)

# Regla por defecto
all: $(TARGET)

# Cómo construir el objetivo final (el ejecutable)
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Cómo limpiar los archivos compilados, para empezar de nuevo
clean:
	rm -f $(TARGET) $(OBJECTS)

# Dependencias (opcional, para este ejemplo no se especifican dependencias explícitas)