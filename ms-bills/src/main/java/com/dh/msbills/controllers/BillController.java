package com.dh.msbills.controllers;

import com.dh.msbills.models.Bill;
import com.dh.msbills.services.BillService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/bills")
@RequiredArgsConstructor
public class BillController {

    private final BillService service;

//    @GetMapping("/all")
//    @PreAuthorize("hasRole('ROLE_USER')")
//    public ResponseEntity<List<Bill>> getAll() {
//        return ResponseEntity.ok().body(service.getAllBill());
//    }

    @GetMapping("/all")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<List<Bill>> getAll() {
        return ResponseEntity.ok().body(service.getAllBill());
    }

    @PostMapping()
 //   @PreAuthorize("hasAuthority('GROUP_PROVIDERS')")
   // @PreAuthorize("hasAnyAuthority('/PROVIDER')")
    public ResponseEntity<Bill> save(@RequestBody Bill bill){
        return ResponseEntity.ok().body(service.save(bill));
    }

    @GetMapping("/findBillsById2")
    public ResponseEntity<List<Bill>> getAllBills(String idBill) {
        return ResponseEntity.ok().body(service.findByidBill(idBill));
    }


    @GetMapping("/findBillsById")
    public ResponseEntity<List<Bill>> getAll(@RequestParam String idBill) {
        return ResponseEntity.ok().body(service.findByidBill(idBill));
    }

}
//asignarle el rol de viewusers