#include <string>
#include <vector>
#include <map>

#include "connspec.h"

namespace lcb
{
%%{
    machine connspec;
    write data;
}%%

lcb_STATUS parse_connspec(const char *specstr, size_t specstr_len, lcb::Connspec &spec)
{
    const char *p = specstr;
    const char *pe = specstr + specstr_len;
    const char *eof = pe;
    int cs;

    const char *scheme;
    const char *bucket;
    const char *kb, *ke, *vb, *ve; /* option key and value boundaries */

    const char *address;
    const char *port;
    lcb::Spechost node;

    %%{
        action s1 { scheme = fpc; }
        action s2 { spec.set_scheme(std::string(scheme, fpc)); }
        action b1 { bucket = fpc; }
        action b2 { spec.set_bucket(std::string(bucket, fpc)); }

        action add_host   { spec.add_host(node); node = {}; }
        action add_option { spec.set_option(std::string(kb, ke), std::string(vb, ve)); }

        action flag_ipv4  { node.htype = LCB_HOST_TYPE_IPV4; }
        action flag_ipv6  { node.htype = LCB_HOST_TYPE_IPV6; }
        action flag_dns   { node.htype = LCB_HOST_TYPE_DNS; }

        action flag_http  { node.btype = LCB_BOOTSTRAP_TYPE_HTTP; }
        action flag_mcd   { node.btype = LCB_BOOTSTRAP_TYPE_MCD; }
        action flag_https { node.btype = LCB_BOOTSTRAP_TYPE_HTTPS; }
        action flag_mcds  { node.btype = LCB_BOOTSTRAP_TYPE_MCDS; }

        action h1 { address = fpc; }
        action h2 { node.hostname = std::string(address, fpc); }
        action p1 { port = fpc; }
        action p2 { node.port = std::stoi(std::string(port, fpc)); }

        action k1 { kb = fpc; }
        action k2 { ke = fpc; }
        action v1 { vb = fpc; }
        action v2 { ve = fpc; }

        dec_octet =    digit {1,2} |
            '1'        digit {2}   |
            '2'  [0-4] digit       |
            '25' [0-5];

        ipv4_address = dec_octet "." dec_octet "." dec_octet "." dec_octet ;

        h16 = xdigit {1,4} ;
        ls32 = ( h16 ':' h16 ) | ipv4_address ;

        ipv6_address =                     ( h16 ':' ){6} ls32 |
                                      '::' ( h16 ':' ){5} ls32 |
            (                  h16 )? '::' ( h16 ':' ){4} ls32 |
            ( ( h16 ':' ){0,1} h16 )? '::' ( h16 ':' ){3} ls32 |
            ( ( h16 ':' ){0,2} h16 )? '::' ( h16 ':' ){2} ls32 |
            ( ( h16 ':' ){0,3} h16 )? '::'   h16 ':'      ls32 |
            ( ( h16 ':' ){0,4} h16 )? '::'                ls32 |
            ( ( h16 ':' ){0,5} h16 )? '::'                h16  |
            ( ( h16 ':' ){0,6} h16 )? '::';

        port =           digit {1,4} |
                   [1-5] digit {4}   |
            '6'    [0-4] digit {3}   |
            '65'   [0-4] digit {2}   |
            '655'  [0-2] digit       |
            '6553' [0-5] ;

        unreserved = alpha | digit | '-' | [._~] ;
        pct_encoded  = "%" xdigit {2} ;
        sub_delims = [!$&'()*+] ;
        reg_name = ( unreserved | pct_encoded | sub_delims ) + ;

        bootstrap = 'https'i %flag_https | 'http'i %flag_http | 'mcds'i %flag_mcds | 'mcd'i %flag_mcd;

        host = (
            ( (reg_name %flag_dns | '[' ipv6_address ']' %flag_ipv6 | ipv4_address %flag_ipv4 ) >h1 %h2 )
            ( ':' port >p1 %p2 ) ?
            ( '=' bootstrap ) ?
        ) %add_host | '';
        hosts = host | host ( [,;] host ) +;

        bucket = ( alpha | digit | [_.%] | '-' )+ >b1 %b2 ;

        scheme = ( ( alpha | '+' )+ >s1 %s2 ':')  ;

        key =   ( [a-z_] ) + >k1 %k2 ;
        value = ( [^?=&] ) * >v1 %v2 ;

        option = ( key '=' value ) %add_option | '';
        options = option | option ( '&' option ) + ;

        main :=  (scheme '//') ? (hosts ? ( '/' bucket '/'?) ? ) ? ( '?' options ? ) ? ;

        write init;
        write exec;
    }%%



    if (p != eof || cs < %%{ write first_final; }%%) {
        return LCB_EINVAL;
    }
    return LCB_SUCCESS;
}
} // namespace lcb
