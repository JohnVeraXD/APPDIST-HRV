package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;

@Entity
@Table(name = "EnergyReport")
@Data
@NoArgsConstructor
public class EnergyReport {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "consumptionData", nullable = true, unique = true) 
    private Array consumptionData; 
 
    
}    
