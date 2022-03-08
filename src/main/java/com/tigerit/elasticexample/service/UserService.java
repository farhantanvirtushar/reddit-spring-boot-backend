package com.tigerit.elasticexample.service;

import com.tigerit.elasticexample.model.User;
import net.minidev.json.JSONObject;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {

    private final String elasticUrl = "http://192.168.5.198:9200";
    private RestTemplate restTemplate;
    public UserService(){
        this.restTemplate = new RestTemplate();
    }

    public User findByUsername(String username) {
        try {
            System.out.println("finding user by username");
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

            Map<String, Object> query = new HashMap<String, Object>();

            query.put("query", new HashMap<String ,Object>(){{
                put("match",new HashMap<String,Object>(){{
                    put("username","n_a1");
                }});
            }});
//           String query = "{\n" +
//                   "    \"query\": {\n" +
//                   "        \"match\": {\n" +
//                   "            \"username\": \"n_a1\"\n" +
//                   "        }\n" +
//                   "    }\n" +
//                   "}";

//            System.out.println(query);

            this.restTemplate = new RestTemplate();

            HttpEntity<Map<String,Object>> entity = new HttpEntity<Map<String,Object>>(query, headers);

            System.out.println(" headers : "+entity.getHeaders());
            System.out.println(" body : "+entity.getBody());

            ResponseEntity<String> responseEntity = restTemplate.exchange(elasticUrl + "/reddit_user/_search", HttpMethod.GET, entity, String.class);

            System.out.println("response : "+responseEntity.getBody().toString());
//            return responseEntity.getBody();
            return new User();
        } catch (Exception exception) {

            System.out.println(exception);
            return new User();
        }
    }
}
