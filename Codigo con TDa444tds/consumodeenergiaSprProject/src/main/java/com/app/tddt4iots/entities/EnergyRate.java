package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;

@Entity
@Table(name = "EnergyRate")
@Data
@NoArgsConstructor
public class EnergyRate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "kw", nullable = true, unique = true) 
    private Float kw; 
 
    
}    
