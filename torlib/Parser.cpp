/*-
 * Copyright (c) 2021, Zano project, https://zano.org/
 * Copyright (c) 2021, Mikhail Butolin, bml505@hotmail.com
 * Copyright (c) 2016 Petr Benes https://github.com/wbenny/mini-tor
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of this program nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include "Parser.h"

Parser::Parser()
{
	list_control_words[control_words::not_determined] = " ";
	list_control_words[control_words::onion_key] = "onion-key";
	list_control_words[control_words::signing_key] = "signing-key";
	list_control_words[control_words::begin_public_key] = "-----BEGIN RSA PUBLIC KEY-----";
	list_control_words[control_words::end_public_key] = "-----END RSA PUBLIC KEY-----";
	list_control_words[control_words::ntor_onion_key] = "ntor-onion-key";
}

vector<string> Parser::ParsString(const string& in_str, string del)
{
	vector<string> ret_data;
	boost::split(ret_data, in_str, boost::is_any_of(del));
	return ret_data;
}

std::tm Parser::GetValidUntil(const string& in_str)
{
	size_t pos = in_str.find(preamble_control_words);
	string date_time;
	std::tm date;
	if (pos != string::npos)
	{
		date_time = in_str.substr(pos + std::strlen(preamble_control_words.c_str()) + 1, 19);
		std::istringstream str_date(date_time);
		str_date >> std::get_time(&date, "%Y-%m-%d %H:%M:%S");
		if (str_date.fail()) {
			BOOST_LOG_TRIVIAL(warning) << "Parse failed date file consensus";
		}
		else {
			BOOST_LOG_TRIVIAL(debug) << "Date file consensus: " << std::put_time(&date, "%c");
		}
	}
	return date;
}
bool Parser::SetOnionRouterKeys(shared_ptr<OnionRouter> onion_node, vector<string>& in_data)
{
	control_words current_location = control_words::not_determined;
	string current_key = "";
	for (string line : in_data)
	{
		if (line == list_control_words[control_words::onion_key])
		{
			current_location = control_words::onion_key;
			continue;
		}
		if (line == list_control_words[control_words::signing_key])
		{
			current_location = control_words::signing_key;
			continue;
		}
		if (line == list_control_words[control_words::begin_public_key]) continue;
		if (line == list_control_words[control_words::end_public_key])
		{
			if (current_location == control_words::onion_key) onion_node->SetOnionKey(current_key);
			if (current_location == control_words::signing_key)	onion_node->SetSignigKey(current_key);
			current_location = control_words::end_public_key;
		}
		if (line.find(list_control_words[control_words::ntor_onion_key]) != string::npos)
		{
			current_location = control_words::ntor_onion_key;
			vector<string> res_pars = ParsString(line, " ");
			if (res_pars.size() > 1 && res_pars[1].length() > 2) onion_node->SetNtorOnionKey(res_pars[1]);
		}
		if (current_location == control_words::onion_key || current_location == control_words::signing_key)	current_key += line;
	}
	return true;
}

vector<string> Parser::SearchOnionRouter(vector<string>& in_data, bool random, int or_port, int dir_port, string sh_ip, vector<string> flags)
{
	int index;
	if (random) index = Util::GetRandom() % in_data.size();
	else index = 0;
	vector<string> str_data;
	if (in_data.size() < index) return str_data;
	BOOST_LOG_TRIVIAL(debug) << "Search Onion Router ip=" << sh_ip << " or_port=" << or_port << " dir_port=" << dir_port;
	do
	{
		string line = in_data[index];
		if (!line.empty() && line.length() > 2)
		{
			//string control_char = std::to_string(line[0] + line[1]);
			string control_char;// = std::to_string(line[0]);
			control_char.push_back(line[0]);
			control_char.push_back(line[1]);
			boost::trim(control_char);
			if (control_char.length() == 1 && control_char[0] == static_cast<char>(entry_type::entry_r))
			{
				// Search parameters
				bool dop_par = false;
				for (int i = 0; i < 5 && !dop_par; ++i)
				{
					control_char.clear();
					control_char.push_back(in_data[index + i][0]);
					control_char.push_back(in_data[index + i][1]);
					boost::trim(control_char);
					if (control_char.length() == 1 && control_char[0] == static_cast<char>(entry_type::entry_s))
					{
						dop_par = true;
						for (unsigned j = 0; j < flags.size() && dop_par; ++j)
						{
							string s = in_data[index + i];
							size_t pos = in_data[index + i].find(flags[j]);
							dop_par = pos != std::string::npos;
						}
					}
				}
				if (!dop_par)
				{
					++index;
					continue;
				}					
				// Search by conditions 
				str_data = ParsString(line, " ");
				if (str_data.size() > 1)
				{
					if (or_port > 0) dop_par = std::stoi(str_data[static_cast<int>(entry_r_type::entry_r_or_port)]) == or_port;
					if (dir_port > 0) dop_par = std::stoi(str_data[static_cast<int>(entry_r_type::entry_r_dir_port)]) == dir_port;
					if (dop_par && sh_ip.length() > 0) dop_par = str_data[static_cast<int>(entry_r_type::entry_r_ip)] == sh_ip;

					if (dop_par)
					{
						BOOST_LOG_TRIVIAL(debug) << "---------------- SearchOnionRouter Selected --------------------";
						BOOST_LOG_TRIVIAL(debug) << "nickname=" << str_data[static_cast<int>(entry_r_type::entry_r_nickname)];
						BOOST_LOG_TRIVIAL(debug) << "ip=" << str_data[static_cast<int>(entry_r_type::entry_r_ip)];
						BOOST_LOG_TRIVIAL(debug) << "or_port=" << std::stoi(str_data[static_cast<int>(entry_r_type::entry_r_or_port)]);
						BOOST_LOG_TRIVIAL(debug) << "dir_port=" << std::stoi(str_data[static_cast<int>(entry_r_type::entry_r_dir_port)]);
						BOOST_LOG_TRIVIAL(debug) << "----------------------------------------------------------------";
						return str_data;
					}
				}
			}
		}
		++index;
	} while (in_data.size() > index);
	return str_data;
}
shared_ptr<OnionRouter> Parser::GetOnionRouter(vector<string>& in_data, bool random, int or_port, int dir_port, string sh_ip, vector<string> flags)
{
	shared_ptr<OnionRouter> retOn = make_shared<OnionRouter>();
	vector<string> data_node;
	for (int i = 0; i < 10 && data_node.size() == 0; ++i)
		data_node = SearchOnionRouter(in_data, random, or_port, dir_port, sh_ip, flags);
	if (data_node.size() > 0)
	{
		//vector<string> str_data = ParsString(in_data[index], " ");
		retOn->nickname = data_node[static_cast<int>(entry_r_type::entry_r_nickname)];
		retOn->identity = Util::Base64Decode(data_node[static_cast<int>(entry_r_type::entry_r_identity)]);
		retOn->digest = data_node[static_cast<int>(entry_r_type::entry_r_digest)];
		retOn->publication_date = data_node[static_cast<int>(entry_r_type::entry_r_publication_date)];
		retOn->publication_time = data_node[static_cast<int>(entry_r_type::entry_r_publication_time)];
		retOn->ip = data_node[static_cast<int>(entry_r_type::entry_r_ip)];
		retOn->or_port = std::stoi(data_node[static_cast<int>(entry_r_type::entry_r_or_port)]);
		retOn->dir_port = std::stoi(data_node[static_cast<int>(entry_r_type::entry_r_dir_port)]);
		//retOn->item_count = str_data[router_status_entry_r_item_count];		
	}
	return move(retOn);
}

