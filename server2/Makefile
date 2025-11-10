CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -pedantic -g
LIBS = -lssl -lcrypto
TARGET = server
SOURCES = main.cpp Logger.cpp ClientDB.cpp ClientSession.cpp Server.cpp
HEADERS = server.h
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LIBS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
