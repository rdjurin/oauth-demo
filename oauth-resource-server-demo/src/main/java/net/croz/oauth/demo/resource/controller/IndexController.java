package net.croz.oauth.demo.resource.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class IndexController {

    @GetMapping("/secured")
    public String index(Principal principal, Model model) {
        model.addAttribute("principal", ((OAuth2AuthenticationToken) principal).getPrincipal());
        return "secured";
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

}
