package com.hydrospark.hydrospark.controllers;


import com.hydrospark.hydrospark.configuration.EmailService;
import com.hydrospark.hydrospark.entities.Hydrospark;
import com.hydrospark.hydrospark.entities.Product;
import com.hydrospark.hydrospark.entities.SubProducts;
import com.hydrospark.hydrospark.entities.User;
import com.hydrospark.hydrospark.repositories.HydrosparkRepo;
import com.hydrospark.hydrospark.repositories.ProductRepo;
import com.hydrospark.hydrospark.repositories.UserRepo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Part;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.sql.rowset.serial.SerialBlob;
import java.io.IOException;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/")
public class Home {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private HydrosparkRepo hydrosparkRepo;
    @Autowired
    private ProductRepo productRepo;

    @Autowired
    private EmailService emailService;

    @GetMapping("/try")
    public String tryHtml(){
        return "abc.html";
    }
    @GetMapping("/")
    public String home(Model model,HttpSession session) throws SQLException {
//        email="sachin@hydrospark.org";
//        password="Sachin@10";

        List<Product> products=productRepo.findAll();
        List<Map<String,String>> base64Images = new ArrayList<>();
        for(Product prod:products){
            Blob blob = new SerialBlob(prod.getProdImg());
            byte[] bytes = blob.getBytes(1, (int) blob.length());
            String base64Image = Base64.getEncoder().encodeToString(bytes);
            Map<String,String> prodDetails=new HashMap<>();
            prodDetails.put("img",base64Image);
            prodDetails.put("prodName",prod.getProductName());
            prodDetails.put("url","/product/productdetails/"+prod.getProductName());
            base64Images.add(prodDetails);
        }
        Hydrospark hyd=hydrosparkRepo.findByName("hydrospark").get(0);
        Blob blob = new SerialBlob(hyd.getImg());
        byte[] bytes = blob.getBytes(1, (int) blob.length());
        String base64Image = Base64.getEncoder().encodeToString(bytes);
        model.addAttribute("img", base64Image);


        model.addAttribute("product", base64Images);

        return "home.html";
    }


    @GetMapping("hydrospark")
    public String hydrospark(){
        return "hydrospark";
    }
    @PostMapping("hydrospark")
    public String postHydrospark(HttpServletRequest request,HttpSession session) throws ServletException, IOException {
        String name=request.getParameter("name");


        Part filePart = request.getPart("img");
        byte[] imageBytes = filePart.getInputStream().readAllBytes();
        Hydrospark hydrospark=new Hydrospark(name,imageBytes);
        hydrosparkRepo.save(hydrospark);
        return "redirect:/";
    }

    @PostMapping("/search")
    public void getSearch(){
        System.out.println("Search..........");
    }
    @GetMapping("/signin")
    public String getSignIn(Model model) throws SQLException {

        Hydrospark hyd=hydrosparkRepo.findByName("hydrospark").get(0);
        Blob blob = new SerialBlob(hyd.getImg());
        byte[] bytes = blob.getBytes(1, (int) blob.length());
        String base64Image = Base64.getEncoder().encodeToString(bytes);
        model.addAttribute("img", base64Image);
        return "signin.html";
    }

    @PostMapping("/signin")
    public String postSignIn(HttpServletRequest request,Model model,HttpSession session){
        System.out.println("SignIn");
        String redirectURL= (String) session.getAttribute("redirectURL");
        if (redirectURL==null){
            redirectURL="redirect:/";
        }
        else{
            redirectURL="redirect:/"+redirectURL;
        }
        String email=request.getParameter("Email");
        String password=request.getParameter("Password");
        List<User> user=userRepo.findAllByEmailAndPassword(email,password);

        if(user.size()==1){
            session.setAttribute("user",email);
            session.removeAttribute("employee");
            return redirectURL;
        }
        else{
            System.out.println(user.size());
            model.addAttribute("error","Wrong or Invalid email address. Please correct and try again.");
        }
        return "signin.html";
    }

    @GetMapping("/signup")
    public String getRegister(){
        System.out.println("get Signup");
        return "register.html";
    }

    @PostMapping("/signup")
    public String postRegister(HttpServletRequest request, Model model,HttpSession session){
        System.out.println("Post Signup");
        String email=request.getParameter("Email");
        String password=request.getParameter("Password");
        String firstName=request.getParameter("firstName");
        String lastName=request.getParameter("lastName");
        String confirmPassword=request.getParameter("confirmPassword");
        long number= Long.parseLong(request.getParameter("number"));
        List<User> user=userRepo.findByEmail(email);
        if(user.size()>0){
            model.addAttribute("error","User is Already exist");
            return "register.html";
        }
        else{
            /*
              How password should be
                The password length to be between 8 and 16 characters.
                At least one uppercase letter.
                At least one lowercase letter.
                At least one digit.
                At least one special character.
             */
            String passwordPattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!])[A-Za-z\\d@#$%^&+=!]{8,}$";
//            String passwordPattern ="^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$";
            Pattern pattern = Pattern.compile(passwordPattern);
            Matcher matcher = pattern.matcher(password);
            if(!password.equals(confirmPassword)){
                System.out.println("Password and confirm password not matching");
                model.addAttribute("error","Password and confirm password do not match.");
                return "register.html";
            }

           if (matcher.matches()){
                User newUser=new User(firstName,lastName,email,password,number);
                Random random = new Random();
                String otp = 1000 + random.nextInt(9000)+"";
                session.setAttribute("otp",otp);
                String subject="Hydrospark Account OTP"+otp;
                String body="Hello, " + email + ".\n"
                        + "OTP: "+ otp +"\n\n"
                        + "Thanks and regards,\n"
                        + "Hydrospark inno.";
                emailService.sendEmail(session,email,subject,body);
                session.setAttribute("userDetails",newUser);
               System.out.println("Here in Signup after all correct");
                return "redirect:/validate";
            }
            else{
                model.addAttribute("error","Password is not as expected");
                return "register.html";
            }


        }
//        return "redirect:/";
    }

    @GetMapping("/forgetpassword")
    public String getForgetPassword(){
//        Random random = new Random();
//        String otp = 1000 + random.nextInt(9000)+"";
//        session.setAttribute("otp",otp);
//        String subject="Hydrospark Account OTP"+otp;
//        String body="Hello, " + email + ".\n"
//                + "OTP: "+ otp +"\n\n"
//                + "Thanks and regards,\n"
//                + "Hydrospark inno.";
//        emailService.sendEmail(session,email,subject,body);
        return "forgetpassword.html";
    }

    @PostMapping("/forgetpassword")
    public String postForgetPassword(HttpServletRequest request, Model model,HttpSession session){
        String email=request.getParameter("Email");
        String password=request.getParameter("Passowrd");
        String cnfPassowrd=request.getParameter("cnfPassowrd");
        String passwordPattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!])[A-Za-z\\d@#$%^&+=!]{8,}$";
//            String passwordPattern ="^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$";
        Pattern pattern = Pattern.compile(passwordPattern);
        Matcher matcher = pattern.matcher(password);
        if(!password.equals(cnfPassowrd)){
            model.addAttribute("error","Password and confirm password do not match.");
            return "redirect:/forgetpassword/";
        }
        if (!matcher.matches()){
            model.addAttribute("error","Password is not as expected");
            return "redirect:/forgetpassword/";
        }
        Random random = new Random();
        String otp = 1000 + random.nextInt(9000)+"";
        session.setAttribute("otp",otp);
        session.setAttribute("cnfPassowrd",cnfPassowrd);
        session.setAttribute("email",email);
        String subject="Hydrospark Account OTP "+otp+" for forget Password";
        String body="Hello, " + email + ".\n"
                + "OTP: "+ otp +"\n\n"
                + "Thanks and regards,\n"
                + "Hydrospark inno.";
        emailService.sendEmail(session,email,subject,body);
        return "validate.html";
    }


    @GetMapping("/validate")
    public String validate(HttpSession session){
        if(session.getAttribute("otp")==null){
            return "redirect:/";
        }

        System.out.println("Here111111111");
        return "validate.html";
    }
    @PostMapping("/validate")
    public String validate(HttpServletRequest request,HttpSession session,Model model){
        System.out.println("invalidate in post");
        String OTP=request.getParameter("OTP");
        String requiredOTP = (String) session.getAttribute("otp");
        System.out.println(OTP+" "+requiredOTP+" "+OTP.equalsIgnoreCase(requiredOTP));
        User newUser= (User) session.getAttribute("userDetails");
        if(OTP.equalsIgnoreCase(requiredOTP)){

            String cnfPassowrd= (String) session.getAttribute("cnfPassowrd");
            String email= (String) session.getAttribute("email");
            if (cnfPassowrd!=null){
                if(userRepo.findByEmail(email).size()>0){
                    User user=userRepo.findByEmail(email).get(0);
                    user.password=cnfPassowrd;
                    userRepo.save(user);
                }
                else{
                    model.addAttribute("error","User not registered");
                }
                return "redirect:/signin";
            }
            else {


                userRepo.save(newUser);
                session.removeAttribute("userDetails");
                session.removeAttribute("otp");
                session.setAttribute("user", newUser.email);
                return "redirect:/";
            }
        }
        model.addAttribute("error","Wrong OTP!");
        return "validate.html";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session){
        session.invalidate();
        return  "redirect:/";
    }







    @GetMapping("/search")
    public String searchProduct(@RequestParam String query,Model model) throws SQLException {
//        System.out.println(query);
        return "redirect:/product/"+query;
//
    }

    @GetMapping("/profile")
    public String Userprofile(HttpSession session,Model model){
        String user=(String) session.getAttribute("user");
        if(session.getAttribute("user")==null){
            return "redirect:/";
        }
        if(user!=null){
            User userProfile=userRepo.findByEmail(user).get(0);
            System.out.printf(userProfile.email);
            model.addAttribute("firstName",userProfile.firstName);
            model.addAttribute("lastName",userProfile.lastName);
            model.addAttribute("email",userProfile.email);
            model.addAttribute("password",userProfile.password);
            model.addAttribute("phoneNumber",userProfile.number);

        }
        return "profile.html";
    }
    @GetMapping("/error")
    public String error(){
        return "unauthorized.html";
    }

}
