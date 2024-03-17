package com.app.tddt4iots.repository;
 
 import com.app.tddt4iots.entities.UserAccount;
 import org.springframework.data.jpa.repository.JpaRepository;
 import java.util.*;
import java.lang.*;

 public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {
 }
