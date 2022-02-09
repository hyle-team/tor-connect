#pragma once
#include "Util.h"

class HTTPClient : public std::enable_shared_from_this<HTTPClient>
{
    tcp::resolver resolver_;
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_; // (Must persist between reads)
    http::request<http::empty_body> req_;    
    int timeout_op = 0;
    http::response<http::string_body> res_;
    bool error_operations;

    void OnResolve(beast::error_code ec, tcp::resolver::results_type results);
    void OnConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type);
    void OnWrite(beast::error_code ec, std::size_t bytes_transferred);
    void OnRead(beast::error_code ec, std::size_t bytes_transferred);
    void OnFail(beast::error_code ec, char const* what);

public:
    explicit HTTPClient(net::io_context& ioc) : resolver_(net::make_strand(ioc)), stream_(net::make_strand(ioc)) {}
    void RunClient(const string host, const int port, const string target, const int timeout = 0 , const int version = 11);
    string GetData();    
};

