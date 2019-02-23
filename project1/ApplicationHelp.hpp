#ifndef APPLICATION_HELP_HPP
#define APPLICATION_HELP_HPP

#include <cstdint>
#include <vector>
#include <string>
#include "CommandLineArgument.hpp"

struct ApplicationVersion {
    uint32_t m_major;
    uint32_t m_minor;

    ApplicationVersion(uint32_t m_major, uint32_t m_minor)
            : m_major(m_major), m_minor(m_minor) {}
};

struct ApplicationHelp {
    const std::string name;
    const std::string author;
    const std::string about;
    const std::string usage;
    const std::vector<CommandLineArgument> arguments;
    const ApplicationVersion version;

    ApplicationHelp(const std::string &name, const std::string &author, const std::string &about,
                    const std::vector<CommandLineArgument>& arguments, const ApplicationVersion &version, const std::string& usage)
            : name(name), author(author), about(about), usage(usage), arguments(arguments), version(version) {}

    class Builder;
};

class ApplicationHelp::Builder {

    std::string _name;
    std::string _author;
    std::string _about;
    std::string _usage;
    std::vector<CommandLineArgument> _arguments;
    ApplicationVersion _version{1, 0};

    //Builder() {};
public:
    Builder &setName(const std::string &name) {
        _name = name;
        return *this;
    }

    Builder &setAuthor(const std::string &author) {
        _author = author;
        return *this;
    }

    Builder &setAbout(const std::string &about) {
        _about = about;
        return *this;
    }

    Builder &setUsage(const std::string &usage) {
        _usage = usage;
        return *this;
    }

    Builder &setVersion(const ApplicationVersion &version) {
        _version = version;
        return *this;
    }

    Builder &addArgument(const CommandLineArgument &argument) {
        _arguments.emplace_back(argument);
        return *this;
    }

    ApplicationHelp build() {
        return ApplicationHelp(_name, _author, _about, _arguments, _version, _usage);
    }
};

#endif // APPLICATION_HELP_HPP
