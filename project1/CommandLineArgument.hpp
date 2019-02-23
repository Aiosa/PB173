#ifndef COMMAND_LINE_ARGUMENT_HPP
#define COMMAND_LINE_ARGUMENT_HPP

#include <string>

struct CommandLineArgument {
	const char short_name;
    const std::string long_name;
    const std::string help;
    const bool takes_value;

    CommandLineArgument(const char short_name, const std::string &long_name, const std::string &help,
                                             const bool takes_value) : short_name(short_name), long_name(long_name),
                                                                       help(help), takes_value(takes_value) {}

    class Builder;
};

class CommandLineArgument::Builder {

    char _short_name = ' ';
    std::string _long_name;
    std::string _help;
    bool _takes_value = false;

    //Builder() {}; exists by default

public:
    Builder& setLongName (const std::string& name) {
        _long_name = name;
        return *this;
    }

    Builder& setShortName (const char shortName) {
        _short_name = shortName;
        return *this;
    }

    Builder& setHelp (const std::string& help) {
        _help = help;
        return *this;
    }

    Builder& setTakesValue (const bool takesValue) {
        _takes_value = takesValue;
        return *this;
    }

    CommandLineArgument build() {
        return CommandLineArgument(_short_name, _long_name, _help, _takes_value);
    }
};


#endif // COMMAND_LINE_ARGUMENT_HPP
