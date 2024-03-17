package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;
import java.util.Date; 

@Entity
@Table(name = "UserAccount")
@Data
@NoArgsConstructor
public class UserAccount {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "email", nullable = true, unique = true, length = 30) 
    private String email; 
 
    @Column(name = "usuario", nullable = false, unique = false, length = 30) 
    private String usuario; 
 
    @Column(name = "nombre", nullable = false, unique = false, length = 30) 
    private String nombre; 
 
    @Column(name = "contrasenia", nullable = false, unique = false, length = 30) 
    private String contrasenia; 
 
    @Column(name = "nombreApellidos", nullable = false, unique = false, length = 30) 
    private String nombreApellidos; 
 
    @Column(name = "urlFoto", nullable = false, unique = false, length = 30) 
    private String urlFoto; 
 
    @Column(name = "iDUser", nullable = false, unique = false, length = 30) 
    private String iDUser; 
 
    @Column(name = "fechacreacion", nullable = false, unique = false) 
    @Temporal(TemporalType.TIMESTAMP) 
    private Date fechacreacion; 
 
    @Column(name = "urlfoto", nullable = false, unique = false, length = 30) 
    private String urlfoto; 
 
    @Column(name = "estado", nullable = false, unique = false, length = 30) 
    private String estado; 
 
    
}    
