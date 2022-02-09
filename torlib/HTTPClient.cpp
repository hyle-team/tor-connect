#include "HTTPClient.h"

// Start the asynchronous operation
void HTTPClient::RunClient(const string host, const int port, const string target, const int timeout, int version)
{
    error_operations = false;
    timeout_op = timeout;
    // Set up an HTTP GET request message
    req_.version(version);
    req_.method(http::verb::get);
    req_.target(target);
    req_.set(http::field::host, host);
    req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver_.async_resolve(host, std::to_string(port),
        beast::bind_front_handler(&HTTPClient::OnResolve, shared_from_this()));
}

void HTTPClient::OnResolve(beast::error_code ec, tcp::resolver::results_type results)
{
    if (ec) return OnFail(ec, "HTTPClient::OnResolve");
    // Set a timeout on the operation
    if (timeout_op > 0) stream_.expires_after(std::chrono::seconds(timeout_op));
    // Make the connection on the IP address we get from a lookup
    stream_.async_connect(results, 
        beast::bind_front_handler(&HTTPClient::OnConnect, shared_from_this()));
}

void HTTPClient::OnConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
{
    if (ec) return OnFail(ec, "HTTPClient::OnConnect");
    if(timeout_op>0) stream_.expires_after(std::chrono::seconds(timeout_op));
    http::async_write(stream_, req_,
        beast::bind_front_handler(&HTTPClient::OnWrite, shared_from_this()));
}

void HTTPClient::OnWrite(beast::error_code ec, std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);
    if (ec) return OnFail(ec, "HTTPClient::OnWrite");
    http::async_read(stream_, buffer_, res_,
        beast::bind_front_handler(&HTTPClient::OnRead, shared_from_this()));
}

void HTTPClient::OnRead(beast::error_code ec, std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);
    if (ec) return OnFail(ec, "HTTPClient::OnRead");
    stream_.socket().shutdown(tcp::socket::shutdown_both, ec);
    if (ec && ec != beast::errc::not_connected)
        return OnFail(ec, "HTTPClient shutdown");
}


void HTTPClient::OnFail(beast::error_code ec, char const* what)
{
    BOOST_LOG_TRIVIAL(error) << what << ": " << ec.message(); 
    res_.clear();
    error_operations = true;
}

string HTTPClient::GetData()
{
    string ret_str = "";
    if (!error_operations)
        ret_str = res_.body().data();
    return ret_str;
}
