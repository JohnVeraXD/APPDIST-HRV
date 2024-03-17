package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;
import java.util.Date; 

@Entity
@Table(name = "ConsumptionHistory")
@Data
@NoArgsConstructor
public class ConsumptionHistory {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "startDate", nullable = true, unique = true) 
    @Temporal(TemporalType.TIMESTAMP) 
    private Date startDate; 
 
    @Column(name = "endDate", nullable = false, unique = false) 
    private Date endDate; 
 
    
}    
