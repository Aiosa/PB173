#include "ApplicationHelp.hpp"
#include "CommandLineArgument.hpp"
#include "Print.hpp"

void printCommandLineArgument(const CommandLineArgument &arg, std::ostream &stream) {

    if (arg.short_name != ' ') {
        stream << " -" << arg.short_name;
    } else {
        stream << "    ";
    }

    if (! arg.long_name.empty()) {
        if (arg.short_name != ' ') {
            stream << ',';
        }
        stream << " --" << arg.long_name;
    }

    if (arg.takes_value) {
        stream << " ARG";
    }

    if (!arg.help.empty()) {
        stream << ' ' << arg.help;
    }
    stream << '\n';
}

void printApplicationHelp(const ApplicationHelp &app, std::ostream &stream) {

    stream << app.name << ' ' << app.version.m_major << '.' << app.version.m_minor << '\n';

    if (!app.author.empty()) {
        stream << app.author << '\n';
    }

    if (!app.about.empty()) {
        stream << app.about << '\n';
    }

    std::vector<const CommandLineArgument*> options;
    std::vector<const CommandLineArgument*> flags;

    for (const CommandLineArgument& arg : app.arguments) {
        if (arg.takes_value) {
            options.emplace_back(&arg);
        } else {
            flags.emplace_back(&arg);
        }
    }

    if (! options.empty()) {
        stream << "\nOptions:\n";
        for (const CommandLineArgument* arg : options) {
            printCommandLineArgument(*arg, stream);
        }
    }

    if (! flags.empty()) {
        stream << "\nFlags:\n";
        for (const CommandLineArgument* arg : flags) {
            printCommandLineArgument(*arg, stream);
        }
    }

    stream << "\nUsage:\n" << app.usage;
}
