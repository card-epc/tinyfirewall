#ifndef CONFIG_H
#define CONFIG_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include "../kmodule/sharedstruct.h"


using std::to_string;

class RuleFile final {
    public:
        explicit RuleFile(std::string_view path = "conf/rule.tb")
            : fs_(path.data(), std::fstream::in | std::fstream::out | std::fstream::app) {
            if (!fs_) {
                std::cerr << "open rule.tb failed" << std::endl;
                exit(0);
            }
        }
        ~RuleFile() { fs_.close(); }
        RuleFile(const RuleFile&) = delete;
        RuleFile(RuleFile&&) = delete;
        RuleFile& operator=(RuleFile&) = delete;

        std::vector<RuleTableItem> parseFile();
        void writeRuletoFile(const RuleTableItem& item);

    private:
        std::fstream fs_;
};


std::vector<RuleTableItem> RuleFile::parseFile() {
    
    std::string str;
    std::stringstream temp;
    std::vector<RuleTableItem> ret;
    RuleTableItem item;
    // uint8_t is the same as uchar in cin/cout
    int scidr, dcidr, protocol, action;

    // sstream because of simple use, don't consider performance issues
    while (getline(fs_, str)) {
        if (!str.empty() && str[0] != '#') {
            temp << str;
            temp >> item.src_ip >> scidr >> item.src_port 
                 >> item.dst_ip >> dcidr >> item.dst_port
                 >> protocol >> action;
            item.src_cidr = scidr, item.dst_cidr = dcidr;
            item.protocol = protocol, item.action = action;
            ret.push_back(item);
            // std::cout << item.src_ip << " " << (int)item.src_cidr << " " << item.src_port << " "
            //           << item.dst_ip << " " << (int)item.dst_cidr << " " << item.dst_port << " "
            //           << (int)item.protocol << " " << (int)item.action << std::endl;
            temp.clear();
        }
    }
    return ret;
}

void RuleFile::writeRuletoFile(const RuleTableItem& item) {
    fs_.clear();
    fs_ << to_string(item.src_ip)   << " " << to_string(item.src_cidr) << " " << to_string(item.src_port) << " "
        << to_string(item.dst_ip)   << " " << to_string(item.dst_cidr) << " " << to_string(item.dst_port) << " "
        << to_string(item.protocol) << " " << to_string(item.action)   << "\n";
    fs_.flush();
}
#endif /* ifndef CONFIG_H */
