#include "testsPCH.h"


using namespace cz;
using namespace spas;

// Default port to use for the tests
#define SERVER_PORT 9000

// A port we know its not available, so we can test listen failure
// On windows we use epmap (port 135)
#define SERVER_UNUSABLE_PORT 135


using namespace cz::spas;

SUITE(CZSPAS)
{

TEST(Service1)
{
	Service io;

}

}
