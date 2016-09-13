library(stringr)
library(urltools)
library(plyr)
library(dplyr)
library(XML)
library(rvest)
library(tm)
library(tools)
library(reshape2)
proxy_data <- read.csv("final_dataset.tsv", header = FALSE, sep = "\t", stringsAsFactors = FALSE, na.strings = c("\\N", " "))
colnames(proxy_data) <- c("label", "sourceaddress", "url")


#Parse the URL and store it into seperate column such as full website url, host name, url path and parameter
parsed_url <- function(df) {
  df$website_url <- paste0(url_parse(df$url)$scheme, "://", url_parse(df$url)$server)
  df$host_name <- url_parse(df$url)$server
  df$url_path <- url_parse(df$url)$path
  df$parameter <- url_parse(df$url)$query
  df$url_path[df$url_path == ""] <- "NULL"
  df$parameter[df$parameter == ""] <- "NULL"
  return(df)
}
proxy_data <- parsed_url(proxy_data)

#Clean the dataset
proxy_data$url <- gsub("[[:space:]]", "", proxy_data$url)
proxy_data$website_url <- gsub("^://$", NA, proxy_data$website_url)
proxy_data$website_url <- gsub(" ", NA, proxy_data$website_url)

proxy_data <- filter(proxy_data, proxy_data$label == "benign" | proxy_data$label == "phish")
proxy_data <- na.omit(proxy_data)
#benign_data <- select(filter(proxy_data, proxy_data$label == "benign"), url)
#phish_data <- select(filter(proxy_data, proxy_data$label == "phish"), url)

#ADDRESS BAR-BASED FEATURES:
######################################################################################
#rule 1: IP Address used instead of domain name
#If IP Address in Domain Name -> Phishing (-1)
#otherwise -> legitimate (1)
######################################################################################
check_ip_add <- function(df) {
  df$ip_add_domain <- grepl("\\d+\\.\\d+\\.\\d+\\.\\d+", df$host_name)
  df$ip_add_domain <- replace(df$ip_add_domain, df$ip_add_domain == TRUE, -1)
  df$ip_add_domain <- replace(df$ip_add_domain, df$ip_add_domain == FALSE, 1)
  return(df)
}
proxy_data <- check_ip_add(proxy_data)


######################################################################################
# rule 2: URL Length
######################################################################################
find_url_length <- function(df) {
  df$url_length <- nchar(df$url)
  return(df)
}
proxy_data <- find_url_length(proxy_data)


######################################################################################
#rule 3: Use of Shortining_Service
#If Shorten URL -> Phishing (-1)
#Otherwise -> Legitimate (1)
######################################################################################
tiny_domain <- function(df) {
  df$shortened_url <- grepl("(http|https)://[a-zA-Z0-9]{1,8}.[a-z]{1,3}/[a-zA-Z0-9]{4,8}$", df$url)
  df$shortened_url <- replace(df$shortened_url, df$shortened_url == TRUE, -1)
  df$shortened_url <- replace(df$shortened_url, df$shortened_url == FALSE, 1)
  return(df)
}
proxy_data <- tiny_domain(proxy_data)


######################################################################################
#rule 4: URL path contains '@' symbol
#If sysmbol present -> Phishing (-1)
#Otherwise -> Legitimate (1)
######################################################################################
url_path_symbol_at <- function(df) {
  df$redirection_symbol_at <- str_detect(df$url_path, pattern = "@")
  df$redirection_symbol_at <- replace(df$redirection_symbol_at, df$redirection_symbol_at == TRUE, -1)
  df$redirection_symbol_at <- replace(df$redirection_symbol_at, df$redirection_symbol_at == FALSE, 1)
  return(df)
}
proxy_data <- url_path_symbol_at(proxy_data)


######################################################################################
#rule 5: URL path contains '//' symbol
#If sysmbol present -> Phishing (-1)
#Otherwise -> Legitimate (1)
######################################################################################
url_path_symbol_slash <- function(df) {
  df$redirection_symbol_dbl_slash <- str_count(df$url_path, pattern = "//")
  df$redirection_symbol_dbl_slash <- replace(df$redirection_symbol_dbl_slash, df$redirection_symbol_dbl_slash >= 1, -1)
  df$redirection_symbol_dbl_slash <- replace(df$redirection_symbol_dbl_slash, df$redirection_symbol_dbl_slash == 0, 1)
  return(df)
}
proxy_data <- url_path_symbol_slash(proxy_data)


######################################################################################
#rule 6: More than one use of '-' symbol in domain name
######################################################################################
check_hyphen_symbol <- function(df) {
  df$hyphen_symbol_domain <- str_count(df$host_name, pattern = "-")
  df$hyphen_symbol_domain <- replace(df$hyphen_symbol_domain, df$hyphen_symbol_domain > 1, -1)
  df$hyphen_symbol_domain <- replace(df$hyphen_symbol_domain, df$hyphen_symbol_domain <= 1, 1)
  return(df)
}
proxy_data <- check_hyphen_symbol(proxy_data)


######################################################################################
#rule 7: Use of multiple sub domains
######################################################################################
multi_sub_domain <- function(df) {
  df$multi_sub_domain <- gsub("^[wW]+.", "", df$host_name)
  df$multi_sub_domain <- gsub(".[a-zA-Z]+$", "", df$multi_sub_domain)
  df$multi_sub_domain <- str_count(df$multi_sub_domain, pattern = "[.]")
  df$multi_sub_domain <- replace(df$multi_sub_domain, df$multi_sub_domain == 0, -1)
  df$multi_sub_domain <- df$multi_sub_domain + 1
  df$multi_sub_domain <- replace(df$multi_sub_domain, df$multi_sub_domain <= 2, 1)
  df$multi_sub_domain <- replace(df$multi_sub_domain, df$multi_sub_domain == 3, 0)
  df$multi_sub_domain <- replace(df$multi_sub_domain, df$multi_sub_domain > 3, -1)
  return(df)
}
proxy_data <- multi_sub_domain(proxy_data)


######################################################################################
#rule 8: http/https is part of domain name
######################################################################################
proto_part_domain <- function(df) {
  df$proto_part_domain <- grepl("[.|-]http|[.|-]http[.|-]|http[.|-]|[.|-]https|[.|-]https[.|-]|https[.|-]", df$host_name)
  df$proto_part_domain <- replace(df$proto_part_domain, df$proto_part_domain == TRUE, -1)
  df$proto_part_domain <- replace(df$proto_part_domain, df$proto_part_domain == FALSE, 1)
  return(df)
}
proxy_data <- proto_part_domain(proxy_data)


######################################################################################
#rule 9: length of the host name
######################################################################################
find_host_name_length <- function(df) {
  df$host_name_length <- nchar(df$host_name)
  return(df)
}
proxy_data <- find_url_length(proxy_data)


######################################################################################
#rule 10: No. of dots in URL path
######################################################################################
count_dots_urlpath <- function(df) {
  df$dots_url_path <- str_count(df$url_path, pattern = "[.]")
  df$dots_url_path <- replace(df$dots_url_path, df$dots_url_path >= 2, -1)
  df$dots_url_path <- replace(df$dots_url_path, df$dots_url_path < 2, 1)
  return(df)
}
proxy_data <- count_dots_urlpath(proxy_data)


######################################################################################
#rule 11: number of slashes in URL
######################################################################################
count_slashes_urlpath <- function(df) {
  df$slashes_url_path <- str_count(df$url_path, pattern = "[/]")
  return(df)
}
proxy_data <- count_slashes_urlpath(proxy_data)


######################################################################################
#rule 12: number of terms in the host name of the URL
######################################################################################
# Calculate the typical number of terms used in domain name

# typical number of terms used in benign urls in dataset

# typical number of terms used in phishing urls in dataset
count_terms_length <- function(host) {
  l <- length(strsplit(host, "\\-|\\.")[[1]])
  if (l <= 4) {
    return(1)  
  } else {
    return(-1)
  }
}
count_terms_hostname <- function(df) {
  terms_host <- ddply(df, c("host_name"), transform, no_of_terms = count_terms_length(host_name))
  return(terms_host)
}
proxy_data <- count_terms_hostname(proxy_data)


######################################################################################
#rule 13: Use of suspicious keyword in url
######################################################################################
# Find the most frequently used words in phishing urls

# urls_text <- Corpus(VectorSource(phish_data$url))
# urls_text <- tm_map(urls_text, tolower)
# url_tokens <- list()
# tokens <- function(x)
# {
#   words <- str_split(x, "[/]|[?]|[.]|[=]|[-]|[_]|[ ]|[:]|[&]|[;]")
#   return(words)
# }
# for (i in 1:length(urls_text))
# {
#   url_tokens[i] <- tokens(urls_text[[i]])  
# }
# rm(i)
# url_tokens <- as.VCorpus(url_tokens)
# url_tokens <- tm_map(url_tokens, removeNumbers)
# url_tokens <- tm_map(url_tokens, removeWords, stopwords("english"))
# url_tokens <- tm_map(url_tokens, removeWords, c("aspx", "org", "net", "images", "htm", "html", "index", "php", "www", "com", "http", "https"))
# url_tokens <- tm_map(url_tokens, stripWhitespace)
# url_tokens <- tm_map(url_tokens, PlainTextDocument)
# dtm <- DocumentTermMatrix(url_tokens)
# tdm <- TermDocumentMatrix(url_tokens)
# freq <- colSums(as.matrix(dtm))
# ord <- order(freq)
#freq[tail(ord, 30)]


find_susp_words <- function(df) {
  df$susp_words_url <- grepl("[/|?|.|=|-| |:|&|;]amp[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]fid[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]rand[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]admin[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]secure[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]account[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]auth[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]userid[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]login[/|?|.|=|-| |:|&|;]|[/|?|.|=|-| |:|&|;]update[/|?|.|=|-| |:|&|;]", df$url, ignore.case = TRUE)
  df$susp_words_url <- replace(df$susp_words_url, df$susp_words_url == TRUE, -1)
  df$susp_words_url <- replace(df$susp_words_url, df$susp_words_url == FALSE, 1)
  return(df)
}
proxy_data <- find_susp_words(proxy_data)


######################################################################################
#rule 14: Number of Results from search engine
######################################################################################
# Find the number of results returned by search engine(www.bing.com)
# hits <- 0
# websites <- unique(proxy_data$website_url)
# give_result_no <- function(query){
#   search_url <- paste("https://www.bing.com/search?q=[", query, "]", sep = "")   
#   CAINFO = paste(system.file(package="RCurl"), "/CurlSSL/ca-bundle.crt", sep = "")
#   script <- getURL(search_url, followlocation = TRUE, cainfo = CAINFO)
#   doc <- htmlParse(script)
#   res <- xpathSApply(doc, '//*/span[@class="sb_count"]', xmlValue)
#   hits <- as.integer(gsub("[^0-9]", "", res))
#   if(length(hits) == 0 || is.na(hits)) {
#     return(0)
#   }else {
#     return(hits)
#   }
# }
# 
# for (i in 1:length(websites))
# {
#   keyword <- websites[i]
#   while(TRUE){
#     no_of_results <- try(give_result_no(keyword), silent=TRUE)
#     if(!is(no_of_results, 'try-error')) break
#   }
#   hits[i] <- no_of_results
# }
# 
# df <- melt(data.frame(websites, hits))
# colnames(df) <- c("website_url", "x", "hits")
# df <- select(df, website_url, hits)
df <- read.csv(file = "website_hits.csv", header = TRUE, sep = ",")
proxy_data <- merge(proxy_data, df)
proxy_data <- proxy_data[,c(2,3,4,1,5:20)]

#sample_proxy_data <- proxy_data[sample(nrow(proxy_data), 1000), ]
#result <- write.table(sample_proxy_data, file = "features_extraction.txt", sep = "\t", quote = FALSE, row.names = FALSE)
