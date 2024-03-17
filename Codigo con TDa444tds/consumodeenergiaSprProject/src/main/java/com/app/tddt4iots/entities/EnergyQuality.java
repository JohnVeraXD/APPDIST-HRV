package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;

@Entity
@Table(name = "EnergyQuality")
@Data
@NoArgsConstructor
public class EnergyQuality {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "EnergyLevels", nullable = true, unique = true) 
    private Float EnergyLevels; 
 
    
}    
