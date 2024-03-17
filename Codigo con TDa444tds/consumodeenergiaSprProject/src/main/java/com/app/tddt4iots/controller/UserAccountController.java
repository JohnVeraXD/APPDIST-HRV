package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.UserAccount;
import com.app.tddt4iots.repository.UserAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/useraccount")
public class UserAccountController {

    @Autowired
    private UserAccountRepository useraccountRepository;

    @GetMapping
    public ResponseEntity<List<UserAccount>> getUserAccount() {
        List<UserAccount> listUserAccount = useraccountRepository.findAll();
        return ResponseEntity.ok(listUserAccount);
    }

    @PostMapping
    public ResponseEntity<UserAccount> insertUserAccount(@RequestBody UserAccount useraccount) {
        UserAccount newUserAccount = useraccountRepository.save(useraccount);
        return ResponseEntity.ok(newUserAccount);
    }

    @PutMapping
    public ResponseEntity<UserAccount> updateUserAccount(@RequestBody UserAccount useraccount) {
        UserAccount upUserAccount = useraccountRepository.save(useraccount);
        if (upUserAccount != null) {
            return ResponseEntity.ok(upUserAccount);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<UserAccount> deletePersons(@PathVariable("id") Long email) {
        useraccountRepository.deleteById(email);
        return ResponseEntity.ok(null);
    }

}
