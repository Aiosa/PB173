#ifndef PRINT_HPP
#define PRINT_HPP

#include <iostream>

#include "ApplicationHelp.hpp"
#include "CommandLineArgument.hpp"

void printCommandLineArgument(const CommandLineArgument &arg, std::ostream &stream);
void printApplicationHelp(const ApplicationHelp &app, std::ostream &stream);

#endif // PRINT_HPP
