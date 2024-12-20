#Исполнительный файл который создаться в итоге после линковки
EXE = isp

# Файлы исходного кода 
ISH = main.cpp modAlphaCipher.cpp

# Заголовочный файл
HEAD = header.h

# Флаги для компиляции
FLAGS = -Wall -g

# Правило для компиляции
%.o: %.cpp 
	g++ $(FLAGS) -c $< -o $@  #в конце стоит имя цели

# Правило для сборки
$(EXE): main.o modAlphaCipher.o
	g++ $(FLAGS) -o $@ $^

# Правило для очистки
clean:
	rm -f *.o $(EXE)
