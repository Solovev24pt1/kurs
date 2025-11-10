CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -I../server
LDFLAGS = -lssl -lcrypto -lUnitTest++

SOURCES = test_server.cpp ../server2/Server.cpp ../server2/ClientDB.cpp ../server2/ClientSession.cpp ../server2/Logger.cpp
TARGET = test_server

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.log

.PHONY: clean
